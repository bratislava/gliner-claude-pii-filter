import json
import subprocess
import sys
from pathlib import Path

HOOK = Path(__file__).resolve().parent.parent / "hooks" / "pii_guard.py"


def run(tool, tool_input, event="PreToolUse"):
    p = subprocess.run([sys.executable, "-I", str(HOOK)], input=json.dumps(
        {"hook_event_name": event, "tool_name": tool, "tool_input": tool_input}),
        capture_output=True, text=True, timeout=10)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)["hookSpecificOutput"] if p.stdout.strip() else None


def decision(cmd):
    out = run("Bash", {"command": cmd, "description": "x"})
    return None if out is None else out["permissionDecision"]


WRAP = [
    "kubectl logs deploy/api -n shop --tail=200",
    "kubectl -n shop logs api-7d9 --since=15m | grep ERROR | tail -n 50",
    "docker logs web --tail 100",
    "journalctl -u nginx -n 200 --no-pager",
    "logcli query '{namespace=\"shop\"}' --limit 500 --since 1h",
    "logcli instant-query 'count_over_time({app=\"api\"}[5m])'",
    "curl -s 'http://localhost:3100/loki/api/v1/query_range?query={app=\"x\"}' | jq .",
    "curl -s -X POST https://grafana.example/api/ds/query -d @q.json",
    "tail -n 500 /var/log/system.log",
    "grep -i error app.log | sort | uniq -c",
    "rg panic logs/",
    "cat build.log 2>/dev/null",
    "zcat app.log.1.gz | head",
    "stern api --no-follow --tail 50",
    "cd /tmp && tail -n 10 x.log",
    "grep ERROR < server.log",
]
DENY = [
    "kubectl logs -f api",
    "tail -f app.log",
    "stern api",
    "logcli query '{app=\"x\"}' --tail",
    "kubectl logs api > out.txt",
    "cat app.log | tee copy.txt",
    "curl -o out.json http://loki:3100/loki/api/v1/query?query=x",
    "cat $(ls *.log)",
    "kubectl logs api; rm -rf /tmp/x",
    "sed -i s/a/b/ app.log",
    "python3 -c 'print(1)' | grep x app.log",
    "docker logs web; docker rm -f web",
]
PASS = [
    "git log --oneline -5",
    "ls -la logs/",
    "kubectl get pods -n shop",
    "npm test",
    "echo hello",
    "find /var/log -name '*.gz'",
]


def test_wraps_log_commands():
    for c in WRAP:
        out = run("Bash", {"command": c, "description": "d", "timeout": 1000})
        assert out and out["permissionDecision"] == "allow", c
        new = out["updatedInput"]
        assert new["timeout"] == 600000
        assert new["description"] == "d"
        assert new["command"].startswith("set -o pipefail; (\n" + c + "\n) 2>&1 | ")
        assert "pii-redact --hook --context-b64 " in new["command"]


def test_denies_unsafe_log_commands():
    for c in DENY:
        assert decision(c) == "deny", c


def test_ignores_unrelated_commands():
    for c in PASS:
        assert decision(c) is None, c


def test_read_and_grep():
    assert run("Read", {"file_path": "/var/log/app.log"})["permissionDecision"] == "deny"
    assert run("Read", {"file_path": "/srv/app/logs/x.txt"})["permissionDecision"] == "deny"
    assert run("Read", {"file_path": "/tmp/audit-log.jsonl"})["permissionDecision"] == "deny"
    assert run("Read", {"file_path": "/Users/x/.claude/projects/a/session.jsonl"}) is None
    assert run("Read", {"file_path": "/repo/src/logger.py"}) is None
    assert run("Grep", {"pattern": "x", "path": "/var/log", "output_mode": "content"})["permissionDecision"] == "deny"
    assert run("Grep", {"pattern": "x", "glob": "*.log", "output_mode": "content"})["permissionDecision"] == "deny"
    assert run("Grep", {"pattern": "x", "path": "/var/log"}) is None  # files_with_matches only
    assert run("Grep", {"pattern": "x", "path": "src", "output_mode": "content"}) is None
