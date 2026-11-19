"""Throughput on a synthetic 10k-line mixed log (run with the venv python)."""
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pii_filter.engine import Engine  # noqa: E402

random.seed(1)
NAMES = ["Ján Novák", "Peter Kováč", "Eva Malá", "Mária Horváthová", "Tomáš Varga", "Lucia Tóthová"]
T = [
    lambda i: f'{{"ts":"2026-11-19T10:{i % 60:02d}:{i % 60:02d}Z","level":"info","msg":"request handled","path":"/api/v1/items/{i}","status":200,"dur_ms":{i % 97},"trace":"{random.getrandbits(64):016x}"}}',
    lambda i: f"2026-11-19T10:00:{i % 60:02d}Z INFO GET /health 200 {i % 9}ms",
    lambda i: f"2026-11-19T10:00:{i % 60:02d}Z WARN slow query took {i % 900}ms on table payments id={i}",
    lambda i: f"2026-11-19T10:00:{i % 60:02d}Z INFO user {random.choice(NAMES).split()[0].lower()}{i % 50}@example.sk logged in from 10.0.{i % 9}.{i % 200}",
    lambda i: f"2026-11-19T10:00:{i % 60:02d}Z ERROR payment {i} failed for {random.choice(NAMES)}: insufficient funds",
    lambda i: f"2026-11-19T10:00:{i % 60:02d}Z DEBUG cache miss key=session:{random.getrandbits(32):08x} ttl=300",
]
lines = [random.choices(T, weights=[40, 25, 10, 10, 5, 10])[0](i) for i in range(10000)]
text = "\n".join(lines)
e = Engine()
e.model.load()
t = time.time()
a = e.analyze(text, budget_s=240)
dt = time.time() - t
print(f"{len(lines)} lines, {len(text) / 1e6:.2f} MB -> {dt:.1f}s ({len(lines) / dt:.0f} lines/s); "
      f"templates={a.stats['unique_templates']} complete={a.model_complete} spans={len(a.spans)}")
from collections import Counter  # noqa: E402
print(Counter(s.label for s in a.spans).most_common())
if "-v" in sys.argv:
    seen = Counter()
    for s in a.spans:
        if s.label in ("SECRET", "DRIVERS_LICENSE", "CARD_NUMBER", "PHONE", "DATE_OF_BIRTH") and seen[s.label] < 3:
            seen[s.label] += 1
            ls = text.rfind("\n", 0, s.start) + 1
            print(s.label, s.source, s.score, repr(text[s.start:s.end]), "|", text[ls:text.find("\n", s.end)][:160])
