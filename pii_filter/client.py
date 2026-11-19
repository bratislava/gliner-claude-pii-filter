"""Client used by the CLI, MCP server and hooks: redact -> (auto-approve | wait for human)."""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

BASE = os.environ.get("PII_BASE_URL", "http://127.0.0.1:8765")
DEFAULT_DEADLINE_S = float(os.environ.get("PII_DEADLINE_S", "570"))


@dataclass
class Result:
    ok: bool                 # True -> output may be shown to Claude
    status: str              # auto_approved | approved | rejected | expired | service_down | error
    output: str
    note: str = ""
    review_url: Optional[str] = None

    def message(self) -> str:
        if self.ok:
            return self.output
        if self.status == "rejected":
            return f"[pii-filter: output rejected by human reviewer]{' Note: ' + self.note if self.note else ''}"
        if self.status == "expired":
            return f"[pii-filter: review not completed in time ({self.note or 'timeout'}); output withheld]"
        if self.status == "service_down":
            return ("[pii-filter: review service down; output withheld. "
                    "Ask the user to check `launchctl print gui/$UID/sk.local.pii-filter`.]" +
                    (f" ({self.note})" if self.note else ""))
        return f"[pii-filter: error; output withheld] {self.note}"


def _req(method: str, path: str, body: Optional[dict] = None, timeout: float = 30.0) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def health(timeout: float = 2.0) -> Optional[dict]:
    try:
        return _req("GET", "/health", timeout=timeout)
    except Exception:
        return None


def redact_and_review(text: str, source: str, context: str = "", kind: str = "auto",
                      deadline_s: float = DEFAULT_DEADLINE_S) -> Result:
    t0 = time.time()
    budget = max(30.0, min(240.0, deadline_s / 2))
    try:
        r = _req("POST", "/process", {"text": text, "source": source, "context": context,
                                      "kind": kind, "budget_s": budget}, timeout=deadline_s)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        return Result(False, "service_down" if e.code == 503 else "error", "", detail)
    except Exception as e:
        return Result(False, "service_down", "", type(e).__name__)

    if r["status"] == "auto_approved":
        return Result(True, "auto_approved", r.get("output", ""))
    rid, url = r["id"], r.get("review_url")
    while True:
        left = deadline_s - (time.time() - t0)
        if left <= 1:
            try:
                _req("POST", f"/reviews/{rid}/expire?why=client+timeout", {}, timeout=5)
            except Exception:
                pass
            return Result(False, "expired", "", "client timeout", url)
        try:
            w = _req("GET", f"/reviews/{rid}/wait?timeout={min(25.0, left - 0.5):.1f}",
                     timeout=min(25.0, left) + 10)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return Result(False, "expired", "", "review vanished", url)
            return Result(False, "error", "", f"HTTP {e.code}", url)
        except Exception as e:
            return Result(False, "service_down", "", type(e).__name__, url)
        st = w["status"]
        if st == "approved":
            return Result(True, st, w.get("output", ""), w.get("note", ""), url)
        if st in ("rejected", "expired"):
            return Result(False, st, "", w.get("note", ""), url)


def scan(text: str, kind: str = "auto") -> dict:
    return _req("POST", "/process", {"text": text, "source": "scan", "kind": kind,
                                     "review": False}, timeout=300)
