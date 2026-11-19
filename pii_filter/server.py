"""Local PII daemon: redaction API + human review UI. Bind to localhost only."""
from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from .engine import Engine, ModelUnavailable
from .review import ReviewStore

HOST = os.environ.get("PII_HOST", "127.0.0.1")
PORT = int(os.environ.get("PII_PORT", "8765"))
ALLOWED_HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
UI = Path(__file__).with_name("ui.html")

log = logging.getLogger("pii_filter.server")
engine = Engine()
store = ReviewStore()
app = FastAPI(title="pii-filter", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def host_guard(request: Request, call_next):
    # DNS-rebinding protection: only answer requests addressed to localhost
    if request.headers.get("host") not in ALLOWED_HOSTS:
        return JSONResponse({"error": "forbidden host"}, status_code=403)
    return await call_next(request)


@app.on_event("startup")
def _load_model() -> None:
    threading.Thread(target=engine.model.load, daemon=True).start()


class ProcessReq(BaseModel):
    text: str
    source: str = "unknown"
    context: str = ""
    kind: str = "auto"          # auto | text | json
    budget_s: float = 240.0
    review: bool = True         # False -> scan only (no output text returned)


class DecisionReq(BaseModel):
    decision: str               # approve | reject
    disabled: List[int] = []
    added: List[Tuple[int, int]] = []
    note: str = ""


class PreviewReq(BaseModel):
    disabled: List[int] = []
    added: List[Tuple[int, int]] = []


@app.get("/health")
def health():
    return {"ok": engine.model.ready, "model_loaded": engine.model.ready,
            "model_error": engine.model.error, "load_seconds": engine.model.load_seconds,
            "pending": len(store.pending())}


@app.post("/process")
def process(req: ProcessReq):
    try:
        a = engine.analyze(req.text, req.kind, use_model=True, budget_s=req.budget_s)
    except ModelUnavailable as e:
        raise HTTPException(503, f"model unavailable: {e}")
    if not req.review:
        return {"status": "scanned", "counts": _counts(a), "model_complete": a.model_complete,
                "kind": a.kind, "notes": a.notes}
    r = store.submit(a, req.source, req.context)
    out = {"id": r.id, "status": r.status, "counts": _counts_from(r), "kind": a.kind,
           "model_complete": a.model_complete}
    if r.status == "auto_approved":
        out["output"] = r.output
    else:
        out["review_url"] = f"http://127.0.0.1:{PORT}/review/{r.id}"
    return out


@app.get("/reviews/{rid}/wait")
def wait(rid: str, timeout: float = 25.0):
    r = store.get(rid)
    if r is None:
        raise HTTPException(404, "unknown or expired review")
    r.event.wait(min(max(timeout, 0), 55))
    d = {"id": r.id, "status": r.status, "note": r.note}
    if r.status == "approved":
        d["output"] = r.output
    return d


@app.post("/reviews/{rid}/expire")
def expire(rid: str, why: str = "client timeout"):
    store.expire(rid, why)
    return {"ok": True}


@app.get("/api/reviews")
def api_list():
    return [r.public(False) for r in store.pending()]


@app.get("/api/reviews/{rid}")
def api_get(rid: str):
    r = store.get(rid)
    if r is None:
        raise HTTPException(404, "unknown or expired review")
    return r.public(r.status == "pending")


@app.post("/api/reviews/{rid}/preview")
def api_preview(rid: str, req: PreviewReq):
    r = store.get(rid)
    if r is None or r.status != "pending":
        raise HTTPException(409, "review is not pending")
    return {"output": store.preview(r, req.disabled, req.added)}


@app.post("/api/reviews/{rid}/decision")
def api_decide(rid: str, req: DecisionReq):
    if req.decision not in ("approve", "reject"):
        raise HTTPException(400, "decision must be approve or reject")
    try:
        r = store.decide(rid, req.decision, req.disabled, req.added, req.note)
    except KeyError:
        raise HTTPException(404, "unknown or expired review")
    return {"status": r.status}


@app.get("/review/{rid}", response_class=HTMLResponse)
@app.get("/reviews", response_class=HTMLResponse)
@app.get("/", response_class=HTMLResponse)
def ui(rid: Optional[str] = None):
    return HTMLResponse(UI.read_text(encoding="utf-8"),
                        headers={"Cache-Control": "no-store",
                                 "Content-Security-Policy": "default-src 'self'; "
                                 "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"})


def _counts(a):
    from collections import Counter
    return dict(Counter(s.label for s in a.spans))


def _counts_from(r):
    return r.public(False).get("counts", {})


def main() -> None:
    import uvicorn
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning", access_log=False,
                timeout_keep_alive=75)


if __name__ == "__main__":
    main()
