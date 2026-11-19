#!/usr/bin/env python3
"""Claude Code hook: route log content through the local PII filter + human review.

PreToolUse
  Bash  - log-producing commands (kubectl logs, stern, docker logs, journalctl, log show, logcli,
          curl/wget to Loki/Grafana, text tools on *.log files) are rewritten to pipe through
          `pii-redact`, which blocks until the human approves. Follow/stream modes, file
          redirects and mixed non-read-only pipelines are denied.
  Read  - direct reads of log files are denied (use mcp__pii-filter__redact_file).
  Grep  - content-mode greps over log files are denied.
PostToolUse
  mcp__*loki*  - MCP tool output is replaced with the reviewed, redacted version.

Stdlib only; fast path exits silently.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shlex
import sys

HOME = os.path.expanduser("~")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PII_REDACT = os.environ.get("PII_REDACT_BIN", os.path.join(HOME, ".local", "bin", "pii-redact"))
BASH_TIMEOUT_MS = 600000

LOG_PATH_RE = re.compile(
    r"(\.log(\.\d+)?(\.gz)?$|\.log\.\d{4}-\d{2}-\d{2}(\.gz)?$|\.ndjson$|\.out$"
    r"|(^|/)(var/log|logs?)(/|$)|(^|/)[^/]*log[^/]*\.jsonl$|\*\.log)", re.I)
EXCLUDE_RE = re.compile(r"(^|/)\.claude(/|$)|^~/\.claude|/node_modules/")

LOKI_URL_RE = re.compile(r"/loki/api/|/api/ds/query|/api/datasources/proxy/|:3100(/|$)")

TEXT_TOOLS = {"cat", "tac", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "zgrep",
              "zcat", "gzcat", "rg", "ag", "awk", "gawk", "sed", "cut", "jq", "yq", "bat", "sort",
              "uniq", "nl", "wc", "tr", "column", "strings", "fold", "fmt", "paste", "comm",
              "base64", "xxd", "rev"}
NEUTRAL = {"cd", "echo", "printf", "true", "date", ":", "test", "["}
PREFIX = {"env", "time", "command", "nohup", "sudo", "nice"}
HTTP_TOOLS = {"curl", "wget", "http", "https", "xh"}

KUBECTL_VALUE_FLAGS = {"-n", "-s", "-v", "--namespace", "--server", "--token", "--context",
                       "--cluster", "--user", "--kubeconfig", "--as", "--as-group", "--output",
                       "-o", "--request-timeout", "-c", "--container", "-l", "--selector"}


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj))
    sys.exit(0)


def deny(reason: str) -> None:
    emit({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                 "permissionDecisionReason": reason}})


def is_log_path(p: str) -> bool:
    p = p.strip("'\"")
    if not p or EXCLUDE_RE.search(p):
        return False
    return bool(LOG_PATH_RE.search(p))


# ------------------------------------------------------------------ bash parsing

def tokenize(cmd: str):
    lx = shlex.shlex(cmd.replace("\n", " ; "), posix=True, punctuation_chars=True)
    lx.whitespace_split = True
    lx.commenters = ""
    return list(lx)


OPS = {";", "&&", "||", "|", "&", "(", ")", ";;", "|&"}


def split_segments(tokens):
    segs, cur, redirs = [], [], []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in OPS or (set(t) <= set("();|&") and t):
            if cur:
                segs.append(cur)
            cur = []
        elif set(t) <= set("<>&") and ">" in t or t in ("<", "<<", "<<<"):
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            redirs.append((t, target))
            i += 1
        else:
            cur.append(t)
        i += 1
    if cur:
        segs.append(cur)
    return segs, redirs


def strip_prefix(seg):
    i = 0
    while i < len(seg) and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[i]) or seg[i] in PREFIX):
        i += 1
    return seg[i:]


def kubectl_sub(args):
    skip = False
    for t in args:
        if skip:
            skip = False
            continue
        if t.startswith("-"):
            if "=" not in t and t in KUBECTL_VALUE_FLAGS:
                skip = True
            continue
        return t
    return None


def classify(seg):
    """-> (is_log_producer, follow, problem) for one pipeline segment."""
    seg = strip_prefix(seg)
    if not seg:
        return False, False, None
    prog, args = os.path.basename(seg[0]), seg[1:]
    flags = set(args)
    if prog == "kubectl":
        sub = kubectl_sub(args)
        if sub == "logs":
            return True, bool(flags & {"-f", "--follow", "--follow=true"}), None
        return False, False, None  # other kubectl handled by kubectl-guard
    if prog == "stern":
        return True, "--no-follow" not in flags, None
    if prog in ("docker", "podman"):
        if "logs" in args:
            return True, bool(flags & {"-f", "--follow"}), None
        return False, False, f"`{prog} {' '.join(args[:2])}` is not read-only"
    if prog == "journalctl":
        return True, bool(flags & {"-f", "--follow"}), None
    if prog == "log" and args[:1] and args[0] in ("show", "stream"):
        return True, args[0] == "stream", None
    if prog == "logcli":
        if args[:1] and args[0] in ("query", "instant-query", "series"):
            return True, bool(flags & {"-t", "--tail", "-f", "--follow"}), None
        return False, False, None
    if prog in HTTP_TOOLS:
        if any(LOKI_URL_RE.search(a) for a in args):
            if any("/loki/api/v1/tail" in a for a in args):
                return True, True, None
            bad = [a for a in args if a in ("-o", "--output", "-O", "--remote-name", "-J")
                   or a.startswith("--output=")]
            if prog == "wget" and not any(a in ("-O-", "-qO-", "--output-document=-") for a in args) \
                    and not ("-O" in args and args[args.index("-O") + 1:args.index("-O") + 2] == ["-"]):
                bad.append("wget without -O-")
            if prog == "curl" and bad:
                return True, False, "curl must print to stdout (no -o/-O)"
            if prog == "wget" and bad:
                return True, False, "wget must print to stdout (use -qO-)"
            return True, False, None
        return False, False, None
    if prog in TEXT_TOOLS:
        hit = any(is_log_path(a) for a in args if not a.startswith("-"))
        follow = prog == "tail" and bool(flags & {"-f", "-F", "--follow"} or
                                         any(re.match(r"^-[a-zA-Z]*[fF]", a) for a in args))
        if prog == "sed" and any(a.startswith("-i") or a == "--in-place" for a in args):
            return hit, follow, "sed -i is not allowed on logs"
        return hit, follow, None
    if prog in NEUTRAL:
        return False, False, None
    return False, False, f"`{prog}` is not an allowed read-only command in a log pipeline"


def handle_bash(ti: dict) -> None:
    cmd = ti.get("command") or ""
    # fast path
    if not re.search(r"kubectl|stern|docker|podman|journalctl|\blog\b|logcli|loki|/api/ds/|"
                     r"datasources/proxy|:3100|\.log|\.ndjson|\.out\b|logs?/|var/log|log[^/\s]*\.jsonl",
                     cmd):
        return
    try:
        tokens = tokenize(cmd)
    except ValueError:
        deny("pii-filter: could not parse this command, and it looks like it reads logs. "
             "Use a simple read-only pipeline (no heredocs or unbalanced quotes).")
        return
    segs, redirs = split_segments(tokens)
    results = [classify(s) for s in segs]
    log_related = any(r[0] for r in results) or any(op.startswith("<") and is_log_path(t)
                                                     for op, t in redirs)
    if ("$(" in cmd or "`" in cmd or "<(" in cmd) and any(is_log_path(t) for t in tokens):
        log_related = True
    if not log_related:
        return
    if "$(" in cmd or "`" in cmd or "<<" in cmd:
        deny("pii-filter: log commands may not use command substitution or heredocs. "
             "Run the log command as a plain read-only pipeline; its output is redacted and "
             "reviewed automatically.")
    if any(r[1] for r in results):
        deny("pii-filter: follow/stream mode can't be reviewed. Use a bounded query instead, "
             "e.g. `kubectl logs <pod> --tail=200`, `--since=15m`, `logcli query --limit 500 "
             "--since 1h`, or `tail -n 500 file.log`.")
    for op, target in redirs:
        if ">" in op and not (target == "/dev/null" or target.isdigit() or target == "-"):
            deny(f"pii-filter: writing log output to a file (`{op} {target}`) bypasses review. "
                 "Print to stdout instead; the output is redacted and reviewed automatically.")
    problems = [r[2] for r in results if r[2]]
    if problems:
        deny("pii-filter: " + "; ".join(problems) + ". Log commands must be a standalone "
             "read-only pipeline (e.g. `kubectl logs <pod> --tail=500 | grep ERROR`). Run "
             "other commands separately.")
    ctx = base64.b64encode(cmd.encode("utf-8")).decode("ascii")
    wrapped = (f"set -o pipefail; (\n{cmd}\n) 2>&1 | {shlex.quote(PII_REDACT)} --hook "
               f"--context-b64 {ctx}")
    new_input = dict(ti)
    new_input["command"] = wrapped
    new_input["timeout"] = BASH_TIMEOUT_MS
    emit({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "permissionDecisionReason": "pii-filter: log output will be redacted and human-reviewed",
        "updatedInput": new_input,
    }})


def handle_read(ti: dict) -> None:
    p = ti.get("file_path") or ""
    if is_log_path(p):
        deny(f"pii-filter: {p} looks like a log file. Use the `mcp__pii-filter__redact_file` "
             "tool (or Bash `tail -n N <file>`, which is redacted automatically) so PII is "
             "removed and the user can review it first.")


def handle_grep(ti: dict) -> None:
    if (ti.get("output_mode") or "files_with_matches") != "content":
        return
    targets = [ti.get("path") or "", ti.get("glob") or ""]
    if any(is_log_path(t) for t in targets if t) or (ti.get("type") or "") == "log" \
            or re.search(r"\.(log|ndjson)\b|log[^/]*\.jsonl", ti.get("glob") or ""):
        deny("pii-filter: content search over log files must go through the PII filter. Use "
             "Bash `grep … <file>` / `rg … <dir>` (redacted and reviewed automatically).")


def handle_post_mcp(data: dict) -> None:
    sys.path.insert(0, REPO)
    from pii_filter import client  # stdlib-only module

    resp = data.get("tool_response")
    raw = resp if isinstance(resp, str) else json.dumps(resp, ensure_ascii=False)
    res = client.redact_and_review(raw, source=f"mcp-hook:{data.get('tool_name')}",
                                   context=json.dumps(data.get("tool_input") or {})[:1000],
                                   kind="auto", deadline_s=560)
    if res.ok:
        if isinstance(resp, str):
            new = res.output
        else:
            try:
                new = json.loads(res.output)
            except Exception:
                new = [{"type": "text", "text": res.output}]
    else:
        msg = res.message()
        if isinstance(resp, dict) and "content" in resp:
            new = {"content": [{"type": "text", "text": msg}]}
        elif isinstance(resp, list):
            new = [{"type": "text", "text": msg}]
        else:
            new = msg
    emit({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedMCPToolOutput": new}})


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except Exception:
        return
    event = data.get("hook_event_name")
    tool = data.get("tool_name") or ""
    ti = data.get("tool_input") or {}
    if event == "PreToolUse":
        if tool == "Bash":
            handle_bash(ti)
        elif tool == "Read":
            handle_read(ti)
        elif tool == "Grep":
            handle_grep(ti)
    elif event == "PostToolUse" and tool.startswith("mcp__") and "loki" in tool.lower() \
            and not tool.startswith("mcp__pii-filter__"):
        handle_post_mcp(data)


if __name__ == "__main__":
    main()
