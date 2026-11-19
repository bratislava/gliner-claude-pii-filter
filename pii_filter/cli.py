"""pii-redact: read stdin (or a file), redact PII, wait for human review, print approved text.

Exit codes: 0 approved/auto-approved, 3 rejected, 4 review service down, 5 review timed out, 6 error.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import sys

from .client import DEFAULT_DEADLINE_S, redact_and_review

EXIT = {"rejected": 3, "service_down": 4, "expired": 5, "error": 6}


def read_input(path: str | None) -> str:
    if not path or path == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(path, "rb") as f:
            data = f.read()
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data.decode("utf-8", errors="replace")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="pii-redact", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("file", nargs="?", help="file to redact (default: stdin)")
    p.add_argument("--source", default="cli")
    p.add_argument("--context", default="", help="command/context shown to the reviewer")
    p.add_argument("--context-b64", default=None, help=argparse.SUPPRESS)
    p.add_argument("--hook", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--kind", default="auto", choices=["auto", "text", "json"])
    p.add_argument("--timeout", type=float, default=DEFAULT_DEADLINE_S, help="seconds to wait for review")
    a = p.parse_args(argv)

    context = a.context
    if a.context_b64:
        context = base64.b64decode(a.context_b64).decode("utf-8", "replace")
    if not context and a.file:
        context = f"file: {a.file}"
    source = "bash-hook" if a.hook else a.source

    text = read_input(a.file)
    if not text.strip():
        sys.stdout.write(text)
        return 0
    res = redact_and_review(text, source=source, context=context, kind=a.kind, deadline_s=a.timeout)
    out = res.message()
    sys.stdout.write(out if out.endswith("\n") or not out else out + "\n")
    sys.stdout.flush()
    return 0 if res.ok else EXIT.get(res.status, 6)


def main_exit() -> None:
    sys.exit(main())


if __name__ == "__main__":
    main_exit()
