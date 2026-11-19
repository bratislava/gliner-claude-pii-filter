"""Redaction engine: regex layer + GLiNER2 model, log-aware batching, JSON awareness."""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .masking import build_skeleton
from .regexes import Span, find_regex_spans

log = logging.getLogger("pii_filter.engine")

MODEL_ID = os.environ.get("PII_MODEL_ID", "fastino/gliner2-privacy-filter-PII-multi")

# model label -> (placeholder label, threshold)
MODEL_LABELS: Dict[str, Tuple[str, float]] = {
    "person": ("PERSON", 0.6),
    "address": ("ADDRESS", 0.5),
    "street_address": ("ADDRESS", 0.5),
    "date_of_birth": ("DATE_OF_BIRTH", 0.7),
    "national_id_number": ("NATIONAL_ID", 0.5),
    "passport_number": ("PASSPORT", 0.5),
    "drivers_license_number": ("DRIVERS_LICENSE", 0.5),
    "tax_id": ("TAX_ID", 0.7),
    "bank_account": ("BANK_ACCOUNT", 0.6),
    "card_number": ("CARD_NUMBER", 0.6),
    "phone_number": ("PHONE", 0.6),
    "email": ("EMAIL", 0.6),
    "iban": ("IBAN", 0.6),
    "username": ("USERNAME", 0.9),
    "password": ("SECRET", 0.5),
    "secret": ("SECRET", 0.75),
    "api_key": ("SECRET", 0.75),
    "access_token": ("SECRET", 0.75),
}

# generic account / log words the model likes to tag as USERNAME or PERSON
GENERIC_VALUES = {
    "login", "logout", "logon", "signin", "sign-in", "user", "users", "username", "admin",
    "administrator", "root", "system", "guest", "anonymous", "anon", "nobody", "null", "none",
    "unknown", "default", "service", "serviceaccount", "api", "test", "ok", "error", "info",
    "warn", "debug", "true", "false", "operator", "owner", "client", "server", "app", "bot",
}

LONG_UNIT_WORDS = 300  # units longer than this go through extract_entities_long
BATCH_SIZE = 32


class ModelUnavailable(RuntimeError):
    pass


class Model:
    """Thread-safe lazy wrapper around the GLiNER2 extractor."""

    def __init__(self) -> None:
        self._m = None
        self._lock = threading.Lock()
        self.error: Optional[str] = None
        self.load_seconds: Optional[float] = None

    def load(self) -> None:
        t = time.time()
        try:
            import torch
            from gliner2 import AutoExtractor

            torch.set_num_threads(max(1, (os.cpu_count() or 4) - 2))
            m = AutoExtractor.from_pretrained(MODEL_ID)
            m.to("cpu")  # measured: CPU beats MPS for this model on Apple Silicon
            if hasattr(m, "eval"):
                m.eval()
            self._m = m
            self.load_seconds = round(time.time() - t, 1)
        except Exception as e:  # pragma: no cover - surfaced via /health
            self.error = f"{type(e).__name__}: {e}"
            log.exception("model load failed")

    @property
    def ready(self) -> bool:
        return self._m is not None

    def _require(self):
        if self._m is None:
            raise ModelUnavailable(self.error or "model not loaded")
        return self._m

    @staticmethod
    def _convert(res: Dict[str, Any]) -> List[Span]:
        out: List[Span] = []
        for lab, items in (res.get("entities") or {}).items():
            if lab not in MODEL_LABELS:
                continue
            plabel, thr = MODEL_LABELS[lab]
            for it in items or []:
                conf = float(it.get("confidence", 1.0))
                if conf < thr or it.get("start") is None:
                    continue
                out.append(Span(int(it["start"]), int(it["end"]), plabel, "model", round(conf, 3)))
        return out

    def batch(self, texts: List[str]) -> List[List[Span]]:
        m = self._require()
        with self._lock:
            res = m.batch_extract_entities(texts, list(MODEL_LABELS), batch_size=BATCH_SIZE,
                                           threshold=0.5, include_spans=True,
                                           include_confidence=True)
        return [self._convert(r) for r in res]

    def long(self, text: str) -> List[Span]:
        m = self._require()
        with self._lock:
            res = m.extract_entities_long(text, list(MODEL_LABELS), threshold=0.5,
                                          chunk_size=384, chunk_overlap=64, batch_size=8,
                                          include_spans=True, include_confidence=True)
        return self._convert(res)


# ------------------------------------------------------------------ analysis

@dataclass
class Analysis:
    doc_text: str                       # what the reviewer sees; spans index into this
    spans: List[Span]
    model_complete: bool
    notes: List[str] = field(default_factory=list)
    kind: str = "text"
    render: Callable[[List[Tuple[int, int, str]]], str] = None  # (start,end,placeholder) -> output
    stats: Dict[str, Any] = field(default_factory=dict)


def merge_spans(spans: List[Span]) -> List[Span]:
    """Union overlapping spans; label of the longest (regex wins ties)."""
    if not spans:
        return []
    spans = sorted(spans, key=lambda s: (s.start, -(s.end - s.start)))
    out: List[Span] = []
    groups: List[List[Span]] = []
    for s in spans:
        if out and s.start < out[-1].end:
            groups[-1].append(s)
            out[-1] = Span(out[-1].start, max(out[-1].end, s.end), out[-1].label,
                           out[-1].source, out[-1].score)
        else:
            out.append(Span(s.start, s.end, s.label, s.source, s.score))
            groups.append([s])
    for i, g in enumerate(groups):
        best = max(g, key=lambda s: (s.end - s.start, s.source == "regex", s.score))
        srcs = sorted({s.source for s in g})
        out[i].label = best.label
        out[i].source = "+".join(srcs)
        out[i].score = max(s.score for s in g)
    return out


_TRIM = " \t\r\n\"',;:()[]{}<>"


def _trim(text: str, s: Span) -> Optional[Span]:
    a, b = s.start, s.end
    while a < b and text[a] in _TRIM:
        a += 1
    while b > a and text[b - 1] in _TRIM:
        b -= 1
    if b <= a:
        return None
    return Span(a, b, s.label, s.source, s.score)


def assign_placeholders(doc_text: str, spans: List[Span]) -> List[Tuple[int, int, str]]:
    counters: Dict[str, int] = {}
    seen: Dict[Tuple[str, str], str] = {}
    out = []
    for s in sorted(spans, key=lambda x: x.start):
        val = re.sub(r"\s+", " ", doc_text[s.start:s.end]).strip().lower()
        key = (s.label, val)
        if key not in seen:
            counters[s.label] = counters.get(s.label, 0) + 1
            seen[key] = f"[{s.label}_{counters[s.label]}]"
        out.append((s.start, s.end, seen[key]))
    return out


def splice(text: str, repl: List[Tuple[int, int, str]], offset: int = 0) -> str:
    parts, pos = [], 0
    for s, e, ph in sorted(repl):
        s, e = s - offset, e - offset
        if e <= 0 or s >= len(text):
            continue
        s = max(s, 0)
        parts.append(text[pos:s])
        parts.append(ph)
        pos = max(pos, min(e, len(text)))
    parts.append(text[pos:])
    return "".join(parts)


class Engine:
    def __init__(self, model: Optional[Model] = None):
        self.model = model or Model()

    # -- core: list of (offset, unit_text) -> spans in doc coordinates
    def _analyze_units(self, units: List[Tuple[int, str]], use_model: bool,
                       budget_s: float, notes: List[str],
                       document: bool = False) -> Tuple[List[Span], bool, Dict]:
        t0 = time.time()
        spans: List[Span] = []
        groups: Dict[str, List[Tuple[int, str, Any]]] = {}
        for off, u in units:
            if not u.strip():
                continue
            rs = find_regex_spans(u)
            spans.extend(Span(off + s.start, off + s.end, s.label, s.source, s.score) for s in rs)
            if use_model:
                sk = build_skeleton(u, rs, document)
                groups.setdefault(sk.text, []).append((off, u, sk))

        complete = use_model
        stats = {"units": len(units), "unique_templates": len(groups), "model_units": 0}
        if use_model and groups:
            keys = list(groups)
            short = [k for k in keys if len(k.split()) <= LONG_UNIT_WORDS]
            longs = [k for k in keys if len(k.split()) > LONG_UNIT_WORDS]
            done = 0
            chunk = BATCH_SIZE * 4
            for i in range(0, len(short), chunk):
                if time.time() - t0 > budget_s:
                    complete = False
                    break
                batch = short[i:i + chunk]
                for k, found in zip(batch, self.model.batch(batch)):
                    self._map_back(groups[k], found, spans)
                done += len(batch)
            for k in longs:
                if not complete or time.time() - t0 > budget_s:
                    complete = False
                    break
                self._map_back(groups[k], self.model.long(k), spans)
                done += 1
            stats["model_units"] = done
            if not complete:
                notes.append(f"Model time budget ({budget_s:.0f}s) exceeded: "
                             f"{len(keys) - done} of {len(keys)} unique line templates were "
                             f"checked by regex only.")
        stats["seconds"] = round(time.time() - t0, 2)
        return spans, complete, stats

    @staticmethod
    def _map_back(members, found: List[Span], spans: List[Span]) -> None:
        for off, u, sk in members:
            for f in found:
                a, b = sk.to_orig(f.start, f.end)
                spans.append(Span(off + a, off + b, f.label, f.source, f.score))

    def _finish(self, doc_text: str, spans: List[Span]) -> List[Span]:
        trimmed = [t for t in (_trim(doc_text, s) for s in spans) if t]
        trimmed = [t for t in trimmed if not (t.source == "model" and
                                              doc_text[t.start:t.end].lower() in GENERIC_VALUES)]
        return merge_spans(trimmed)

    # -- public
    def analyze(self, text: str, kind: str = "auto", use_model: bool = True,
                budget_s: float = 240.0) -> Analysis:
        notes: List[str] = []
        if use_model and not self.model.ready:
            raise ModelUnavailable(self.model.error or "model not loaded")
        if kind in ("auto", "json", "loki"):
            obj = _try_json(text) if kind != "text" else None
            if obj is not None:
                return self._analyze_json(obj, text, use_model, budget_s, notes, kind)
        return self._analyze_text(text, use_model, budget_s, notes)

    def _analyze_text(self, text, use_model, budget_s, notes) -> Analysis:
        lines = text.split("\n")
        nonempty = [l for l in lines if l.strip()]
        lens = sorted(len(l) for l in nonempty) or [0]
        loglike = len(nonempty) >= 3 and lens[len(lens) // 2] < 400
        if loglike:
            units, off = [], 0
            for l in lines:
                units.append((off, l))
                off += len(l) + 1
            kind = "log"
        else:
            units, kind = [(0, text)], "document"
        spans, complete, stats = self._analyze_units(units, use_model, budget_s, notes,
                                                     document=kind == "document")
        spans = self._finish(text, spans)
        return Analysis(text, spans, complete, notes, kind,
                        render=lambda repl: splice(text, repl), stats=stats)

    def _analyze_json(self, obj, raw, use_model, budget_s, notes, kind) -> Analysis:
        loki = _is_loki(obj)
        leaves: List[Tuple[list, Any]] = []  # (path, value)
        _collect_leaves(obj, [], leaves, loki)
        # nested JSON strings (e.g. MCP text content) are expanded once
        expanded: List[Tuple[list, str]] = []
        nested: Dict[int, Any] = {}
        for i, (path, val) in enumerate(leaves):
            inner = _try_json(val) if isinstance(val, str) and val[:1] in "[{" else None
            if inner is not None and isinstance(inner, (dict, list)):
                nested[i] = inner
                sub: List[Tuple[list, Any]] = []
                _collect_leaves(inner, [], sub, _is_loki(inner))
                for sp, sv in sub:
                    expanded.append(([*path, ("__nested__", i), *sp], sv))
            else:
                expanded.append((path, val))
        # virtual doc: one leaf per line (newlines inside a leaf are kept; offsets tracked)
        offs, parts, pos = [], [], 0
        for _, v in expanded:
            offs.append(pos)
            parts.append(v)
            pos += len(v) + 1
        doc = "\n".join(parts)
        units = list(zip(offs, parts))
        spans, complete, stats = self._analyze_units(units, use_model, budget_s, notes)
        spans = self._finish(doc, spans)
        indent = 2 if "\n" in raw.strip()[:200] else None

        def render(repl):
            new_obj = json.loads(json.dumps(obj))
            nested_objs = {i: json.loads(json.dumps(o)) for i, o in nested.items()}
            for (path, val), off in zip(expanded, offs):
                new_val = splice(val, repl, off)
                if new_val == val:
                    continue
                if any(isinstance(p, tuple) for p in path):
                    k = next(j for j, p in enumerate(path) if isinstance(p, tuple))
                    _set_path(nested_objs[path[k][1]], path[k + 1:], new_val)
                else:
                    _set_path(new_obj, path, new_val)
            for i, o in nested_objs.items():
                _set_path(new_obj, leaves[i][0], json.dumps(o, ensure_ascii=False))
            return json.dumps(new_obj, ensure_ascii=False, indent=indent)

        return Analysis(doc, spans, complete, notes, "loki_json" if loki else "json",
                        render=render, stats=stats)


def _try_json(text: str):
    s = text.strip()
    if not s or s[0] not in "[{":
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def _is_loki(obj) -> bool:
    try:
        res = obj["data"]["result"]
        return isinstance(res, list) and obj["data"].get("resultType") in ("streams", "matrix", "vector")
    except Exception:
        return False


def _collect_leaves(obj, path, out, loki: bool) -> None:
    if loki:
        for i, stream in enumerate(obj["data"]["result"]):
            for j, v in enumerate(stream.get("values") or []):
                if isinstance(v, list) and len(v) >= 2 and isinstance(v[1], str):
                    out.append((["data", "result", i, "values", j, 1], v[1]))
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            _collect_leaves(v, path + [k], out, False)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _collect_leaves(v, path + [i], out, False)
    elif isinstance(obj, str):
        out.append((path, obj))


def _set_path(obj, path, value) -> None:
    for p in path[:-1]:
        obj = obj[p]
    obj[path[-1]] = value
