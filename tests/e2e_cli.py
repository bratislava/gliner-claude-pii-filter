"""End-to-end: run pii-redact against a live daemon, act as the human reviewer via the API.

Usage: PII_BASE_URL=http://127.0.0.1:8766 python tests/e2e_cli.py
(start a test daemon with PII_PORT=8766 PII_OPEN_BROWSER=0 first)
"""
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request

BASE = os.environ.get("PII_BASE_URL", "http://127.0.0.1:8766")
BIN = os.path.join(os.path.dirname(sys.executable), "pii-redact")
ENV = {**os.environ, "PII_BASE_URL": BASE}


def api(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def reviewer(action, note="", unredact_label=None, delay=1.0):
    def run():
        for _ in range(100):
            time.sleep(0.2)
            items = api("GET", "/api/reviews")
            if items:
                rid = items[0]["id"]
                detail = api("GET", f"/api/reviews/{rid}")
                disabled = [s["id"] for s in detail["spans"] if s["label"] == unredact_label]
                time.sleep(delay)
                api("POST", f"/api/reviews/{rid}/decision",
                    {"decision": action, "disabled": disabled, "added": [], "note": note})
                return
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def cli(text, *args):
    p = subprocess.run([BIN, *args], input=text, capture_output=True, text=True, env=ENV, timeout=120)
    return p.returncode, p.stdout


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  {extra}" if extra and not cond else ""))
    return cond


ok = True
t = time.time()
rc, out = cli("GET /health 200\nGET /ready 200\nGET /metrics 200\n", "--context", "clean")
ok &= check("auto-approve clean output (instant, no review)",
            rc == 0 and out == "GET /health 200\nGET /ready 200\nGET /metrics 200\n" and time.time() - t < 5,
            repr((rc, out)))

pii = ("2026-11-19T10:00:01Z ERROR platba zamietnutá: Ján Novák, jan.novak@gmail.com, "
       "IBAN SK3112000000198742637541, from 85.237.1.2\n2026-11-19T10:00:02Z INFO ok\n")
reviewer("approve")
rc, out = cli(pii, "--context", "test approve")
ok &= check("approve -> redacted output", rc == 0 and "[PERSON_1]" in out and "[EMAIL_1]" in out
            and "[IBAN_1]" in out and "Novák" not in out and "gmail" not in out, repr((rc, out)))

reviewer("approve", unredact_label="IP_ADDRESS")
rc, out = cli(pii, "--context", "test unredact")
ok &= check("reviewer un-redaction is honoured", rc == 0 and "85.237.1.2" in out and "[EMAIL_1]" in out,
            repr((rc, out)))

reviewer("reject", note="too sensitive")
rc, out = cli(pii, "--context", "test reject")
ok &= check("reject -> withheld, exit 3", rc == 3 and "rejected" in out and "too sensitive" in out
            and "Novák" not in out, repr((rc, out)))

rc, out = cli(pii, "--context", "test timeout", "--timeout", "4")
ok &= check("timeout -> withheld, exit 5", rc == 5 and "Novák" not in out and "withheld" in out,
            repr((rc, out)))

env_down = {**ENV, "PII_BASE_URL": "http://127.0.0.1:8799"}
p = subprocess.run([BIN], input=pii, capture_output=True, text=True, env=env_down, timeout=30)
ok &= check("service down -> withheld, exit 4", p.returncode == 4 and "Novák" not in p.stdout
            and "service down" in p.stdout, repr((p.returncode, p.stdout)))

loki = json.dumps({"status": "success", "data": {"resultType": "streams", "result": [
    {"stream": {"namespace": "shop"}, "values": [["1", "login jan.novak@gmail.com"], ["2", "ok"]]}]}})
reviewer("approve")
rc, out = cli(loki, "--context", "loki json")
j = json.loads(out)
ok &= check("loki JSON stays valid + labels intact",
            rc == 0 and j["data"]["result"][0]["values"][0][1] == "login [EMAIL_1]"
            and j["data"]["result"][0]["stream"]["namespace"] == "shop", repr(out))

print("ALL PASS" if ok else "SOME FAILED")
sys.exit(0 if ok else 1)
