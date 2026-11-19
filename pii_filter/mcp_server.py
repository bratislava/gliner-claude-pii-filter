"""MCP server exposing the local PII filter to Claude (stdio)."""
from __future__ import annotations

import asyncio
import gzip
import os
from collections import Counter

from mcp.server.mcpserver import MCPServer

from . import client

MAX_BYTES = 20 * 1024 * 1024

server = MCPServer(
    name="pii-filter",
    instructions=(
        "Local PII redaction (GLiNER2 + Slovak/Czech regexes) with mandatory human review. "
        "Use redact_file for any log file or official document instead of reading it directly; "
        "use redact_text when the user asks to anonymise text. Calls block until the user "
        "approves in the browser (auto-approved when nothing is detected). Placeholders such "
        "as [PERSON_1] are consistent within one result. Never try to recover redacted values."
    ),
)


def _read(path: str) -> str:
    path = os.path.expanduser(path)
    size = os.path.getsize(path)
    if size > MAX_BYTES:
        raise ValueError(f"file is {size} bytes; limit is {MAX_BYTES}. Filter it first "
                         "(e.g. Bash `grep … file | tail -n 2000`, which is auto-redacted).")
    with open(path, "rb") as f:
        data = f.read()
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data.decode("utf-8", errors="replace")


@server.tool()
async def redact_text(text: str, context: str = "") -> str:
    """Redact PII/secrets from text. Blocks until the user approves the redaction in the review UI
    (instant when nothing is detected). Returns the approved redacted text or a withheld notice."""
    res = await asyncio.to_thread(client.redact_and_review, text, "mcp:redact_text",
                                  context or "redact_text")
    return res.message()


@server.tool()
async def redact_file(path: str) -> str:
    """Read a local file (log, .gz log, JSON, text document), redact PII/secrets and return the
    content after the user approves it in the review UI. Use this instead of Read for logs and
    official documents."""
    try:
        text = await asyncio.to_thread(_read, path)
    except Exception as e:
        return f"[pii-filter: cannot read {path}: {e}]"
    res = await asyncio.to_thread(client.redact_and_review, text, "mcp:redact_file", f"file: {path}")
    return res.message()


@server.tool()
async def scan_pii(text: str = "", path: str = "") -> str:
    """Count PII by type in text or a file WITHOUT returning any content (no review needed)."""
    try:
        if path:
            text = await asyncio.to_thread(_read, path)
        r = await asyncio.to_thread(client.scan, text)
    except Exception as e:
        return f"[pii-filter: scan failed: {type(e).__name__}: {e}]"
    counts = r.get("counts", {})
    total = sum(counts.values())
    lines = [f"{total} PII item(s) detected ({r.get('kind')})"]
    lines += [f"- {k}: {v}" for k, v in Counter(counts).most_common()]
    if not r.get("model_complete", True):
        lines.append("(model check incomplete; regex only for part of the input)")
    return "\n".join(lines)


def main() -> None:
    server.run("stdio")


if __name__ == "__main__":
    main()
