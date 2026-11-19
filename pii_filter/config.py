"""User config (config.toml next to the repo root, or $PII_CONFIG). Reloaded when the file changes.

[model.labels]            GLiNER label -> threshold. Only these labels are asked of the model.
[regex] disabled          regex detector labels to turn off, e.g. ["IP_ADDRESS"]
[allow] values            exact values never redacted (case-insensitive)
[allow] patterns          regexes; a span whose whole text matches is never redacted
[allow] email_domains     emails on these domains are never redacted, e.g. ["example.org"]
"""
from __future__ import annotations

import json
import os
import re
import threading
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional

CONFIG_PATH = Path(os.environ.get("PII_CONFIG", Path(__file__).resolve().parent.parent / "config.toml"))

# model label -> (placeholder label, default threshold); the full menu users can enable
MODEL_LABEL_MAP: Dict[str, str] = {
    "person": "PERSON",
    "address": "ADDRESS",
    "street_address": "ADDRESS",
    "national_id_number": "NATIONAL_ID",
    "passport_number": "PASSPORT",
    "drivers_license_number": "DRIVERS_LICENSE",
    "date_of_birth": "DATE_OF_BIRTH",
    "tax_id": "TAX_ID",
    "bank_account": "BANK_ACCOUNT",
    "card_number": "CARD_NUMBER",
    "phone_number": "PHONE",
    "email": "EMAIL",
    "iban": "IBAN",
    "username": "USERNAME",
    "password": "SECRET",
    "secret": "SECRET",
    "api_key": "SECRET",
    "access_token": "SECRET",
}

# Defaults: only what regexes can't find. Structured data (emails, phones, IBAN, RČ/IČO/DIČ,
# cards, public IPs, secrets) is handled by checksum-validated regexes.
DEFAULT_MODEL_LABELS: Dict[str, float] = {
    "person": 0.6,
    "address": 0.5,
    "street_address": 0.5,
    "national_id_number": 0.6,
    "passport_number": 0.6,
    "drivers_license_number": 0.6,
}


@dataclass
class Config:
    model_labels: Dict[str, float] = field(default_factory=lambda: dict(DEFAULT_MODEL_LABELS))
    regex_disabled: List[str] = field(default_factory=list)
    allow_values: List[str] = field(default_factory=list)
    allow_patterns: List[str] = field(default_factory=list)
    allow_email_domains: List[str] = field(default_factory=list)
    _compiled: List[re.Pattern] = field(default_factory=list, repr=False)

    def compile(self) -> "Config":
        self._compiled = []
        for p in self.allow_patterns:
            try:
                self._compiled.append(re.compile(p, re.I))
            except re.error:
                pass
        self._values = {v.strip().lower() for v in self.allow_values}
        self._domains = {d.strip().lower().lstrip("@") for d in self.allow_email_domains}
        return self

    def allowed(self, label: str, value: str) -> bool:
        v = value.strip().lower()
        if v in self._values:
            return True
        if label == "EMAIL" and "@" in v and v.rsplit("@", 1)[1] in self._domains:
            return True
        return any(p.fullmatch(value.strip()) for p in self._compiled)


_lock = threading.Lock()
_cache: Optional[Config] = None
_mtime: Optional[float] = None


def load() -> Config:
    global _cache, _mtime
    try:
        mtime = CONFIG_PATH.stat().st_mtime
    except FileNotFoundError:
        mtime = None
    with _lock:
        if _cache is not None and mtime == _mtime:
            return _cache
        cfg = Config()
        if mtime is not None:
            try:
                data = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))
                labels = (data.get("model") or {}).get("labels")
                if isinstance(labels, dict):
                    cfg.model_labels = {k: float(v) for k, v in labels.items() if k in MODEL_LABEL_MAP}
                cfg.regex_disabled = list((data.get("regex") or {}).get("disabled") or [])
                allow = data.get("allow") or {}
                cfg.allow_values = list(allow.get("values") or [])
                cfg.allow_patterns = list(allow.get("patterns") or [])
                cfg.allow_email_domains = list(allow.get("email_domains") or [])
            except Exception:
                pass  # keep defaults on a broken file; /health reports it
        _cache, _mtime = cfg.compile(), mtime
        return _cache


def _toml_list(items: Iterable[str]) -> str:
    items = list(items)
    if not items:
        return "[]"
    return "[\n" + "".join(f"  {json.dumps(i, ensure_ascii=False)},\n" for i in items) + "]"


def save(cfg: Config) -> None:
    labels = "\n".join(f"{k} = {v}" for k, v in cfg.model_labels.items())
    text = f"""# pii-filter config. Reloaded automatically when saved.
# Available model labels: {", ".join(MODEL_LABEL_MAP)}

[model.labels]
# label = confidence threshold (0-1); remove a line to stop the model looking for it
{labels}

[regex]
# regex detectors to turn off, e.g. ["IP_ADDRESS"]
disabled = {_toml_list(cfg.regex_disabled)}

[allow]
# values never redacted (case-insensitive); "Remember" on the review page appends here
values = {_toml_list(cfg.allow_values)}
# regexes matched against the whole flagged value
patterns = {_toml_list(cfg.allow_patterns)}
# email domains never redacted, e.g. ["example.org"]
email_domains = {_toml_list(cfg.allow_email_domains)}
"""
    tmp = CONFIG_PATH.with_suffix(".toml.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(CONFIG_PATH)


def add_allowed_values(values: Iterable[str]) -> int:
    cfg = load()
    have = {v.strip().lower() for v in cfg.allow_values}
    new = []
    for v in values:
        v = re.sub(r"\s+", " ", v).strip()
        if v and v.lower() not in have:
            have.add(v.lower())
            new.append(v)
    if new:
        cfg = Config(dict(cfg.model_labels), list(cfg.regex_disabled), cfg.allow_values + new,
                     list(cfg.allow_patterns), list(cfg.allow_email_domains))
        save(cfg)
    return len(new)
