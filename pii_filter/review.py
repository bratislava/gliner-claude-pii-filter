"""In-memory review queue + audit log. Originals never touch disk."""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .engine import Analysis, assign_placeholders, merge_spans
from .regexes import Span

AUDIT_PATH = Path(os.environ.get("PII_AUDIT_PATH", Path(__file__).resolve().parent.parent / "audit.jsonl"))
BASE_URL = os.environ.get("PII_BASE_URL", "http://127.0.0.1:8765")
REVIEW_TTL_S = int(os.environ.get("PII_REVIEW_TTL_S", "900"))
OPEN_BROWSER = os.environ.get("PII_OPEN_BROWSER", "1") == "1"

FINAL = {"approved", "auto_approved", "rejected", "expired"}


@dataclass
class Review:
    id: str
    created: float
    source: str
    context: str
    analysis: Optional[Analysis]
    status: str = "pending"
    output: Optional[str] = None
    note: str = ""
    decided: Optional[float] = None
    event: threading.Event = field(default_factory=threading.Event)
    edits: Dict[str, int] = field(default_factory=dict)

    def public(self, with_doc: bool) -> dict:
        a = self.analysis
        d = {
            "id": self.id, "status": self.status, "source": self.source, "context": self.context,
            "created": self.created, "note": self.note,
        }
        if a is not None:
            d.update(kind=a.kind, model_complete=a.model_complete, notes=a.notes, stats=a.stats,
                     counts=dict(Counter(s.label for s in a.spans)))
            if with_doc:
                d["doc_text"] = a.doc_text
                d["spans"] = [{"id": i, "start": s.start, "end": s.end, "label": s.label,
                               "source": s.source, "score": s.score}
                              for i, s in enumerate(a.spans)]
        return d


class ReviewStore:
    def __init__(self) -> None:
        self._r: Dict[str, Review] = {}
        self._lock = threading.Lock()
        threading.Thread(target=self._reaper, daemon=True).start()

    # ------------------------------------------------------------ lifecycle
    def submit(self, analysis: Analysis, source: str, context: str) -> Review:
        r = Review(uuid.uuid4().hex, time.time(), source, context[:2000], analysis)
        if not analysis.spans and analysis.model_complete:
            r.output = analysis.render([])
            self._finish(r, "auto_approved")
            return r  # not stored: nothing to review
        with self._lock:
            self._r[r.id] = r
        self._notify(r)
        return r

    def get(self, rid: str) -> Optional[Review]:
        with self._lock:
            return self._r.get(rid)

    def pending(self) -> List[Review]:
        with self._lock:
            return sorted((r for r in self._r.values() if r.status == "pending"),
                          key=lambda r: r.created)

    def final_spans(self, r: Review, disabled: List[int], added: List[Tuple[int, int]],
                    added_label: str = "MANUAL") -> List[Span]:
        a = r.analysis
        keep = [s for i, s in enumerate(a.spans) if i not in set(disabled)]
        n = len(a.doc_text)
        extra = [Span(max(0, int(s)), min(n, int(e)), added_label, "manual")
                 for s, e in added if int(e) > int(s)]
        return merge_spans(keep + extra)

    def preview(self, r: Review, disabled, added) -> str:
        spans = self.final_spans(r, disabled, added)
        return r.analysis.render(assign_placeholders(r.analysis.doc_text, spans))

    def decide(self, rid: str, decision: str, disabled: List[int], added: List[Tuple[int, int]],
               note: str) -> Review:
        r = self.get(rid)
        if r is None:
            raise KeyError(rid)
        if r.status != "pending":
            return r
        r.note = (note or "").strip()[:2000]
        r.edits = {"unredacted": len(set(disabled)), "added": len(added)}
        if decision == "approve":
            r.output = self.preview(r, disabled, added)
            self._finish(r, "approved")
        else:
            self._finish(r, "rejected")
        return r

    def expire(self, rid: str, why: str = "timeout") -> None:
        r = self.get(rid)
        if r and r.status == "pending":
            r.note = why
            self._finish(r, "expired")

    def _finish(self, r: Review, status: str) -> None:
        r.status = status
        r.decided = time.time()
        a = r.analysis
        self._audit({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "id": r.id, "source": r.source,
            "context": r.context, "decision": status,
            "counts": dict(Counter(s.label for s in a.spans)) if a else {},
            "edits": r.edits, "model_complete": a.model_complete if a else None,
            "chars": len(a.doc_text) if a else 0, "kind": a.kind if a else None,
            "wait_s": round(r.decided - r.created, 1),
        })
        r.event.set()
        # drop the original right away; keep a stub so pollers can read the decision
        if a is not None:
            r.analysis = Analysis("", [], a.model_complete, a.notes, a.kind, None, a.stats)

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _audit(rec: dict) -> None:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    @staticmethod
    def _notify(r: Review) -> None:
        if not OPEN_BROWSER:
            return
        url = f"{BASE_URL}/review/{r.id}"
        counts = Counter(s.label for s in r.analysis.spans)
        summary = ", ".join(f"{v}× {k}" for k, v in counts.most_common(4))
        title = "PII review needed"
        msg = (r.context or r.source)[:120].replace('"', "'").replace("\\", "/")
        try:
            subprocess.Popen(["osascript", "-e",
                              f'display notification "{summary}" with title "{title}" '
                              f'subtitle "{msg}" sound name "Ping"'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.Popen(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    def _reaper(self) -> None:
        while True:
            time.sleep(15)
            now = time.time()
            with self._lock:
                items = list(self._r.values())
            for r in items:
                if r.status == "pending" and now - r.created > REVIEW_TTL_S:
                    self.expire(r.id, "review TTL exceeded")
                if r.status in FINAL and r.decided and now - r.decided > 600:
                    with self._lock:
                        self._r.pop(r.id, None)
