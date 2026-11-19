import json

import pytest

from pii_filter import review as review_mod
from pii_filter.engine import Engine, assign_placeholders
from pii_filter.masking import build_skeleton
from pii_filter.regexes import Span


class FakeModel:
    """Tags the literal word 'Novák' (with optional first name) as PERSON."""
    ready = True
    error = None

    def batch(self, texts):
        return [self._find(t) for t in texts]

    def long(self, text):
        return self._find(text)

    @staticmethod
    def _find(t):
        out, i = [], t.find("Ján Novák")
        while i >= 0:
            out.append(Span(i, i + 9, "PERSON", "model", 0.9))
            i = t.find("Ján Novák", i + 1)
        return out


@pytest.fixture
def engine():
    return Engine(FakeModel())


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(review_mod, "AUDIT_PATH", tmp_path / "audit.jsonl")
    monkeypatch.setattr(review_mod, "OPEN_BROWSER", False)
    return review_mod.ReviewStore()


def render(a):
    return a.render(assign_placeholders(a.doc_text, a.spans))


def test_skeleton_maps_back():
    t = '{"ts":"2026-11-10T10:00:01Z","id":42,"user":"Ján Novák","ip":"10.1.2.3"}'
    sk = build_skeleton(t, [])
    assert "TS" in sk.text and "Ján Novák" in sk.text and "IP" in sk.text
    i = sk.text.index("Ján Novák")
    a, b = sk.to_orig(i, i + 9)
    assert t[a:b] == "Ján Novák"
    j = sk.text.index("TS")
    a, b = sk.to_orig(j, j + 2)
    assert t[a:b] == "2026-11-10T10:00:01Z"


def test_log_lines_dedupe_and_consistent_placeholders(engine):
    lines = [f'2026-11-10T10:00:{i % 60:02d}Z GET /api/items/{i} 200 user=Ján Novák' for i in range(500)]
    lines.append("mail jan@novak.sk and again jan@novak.sk, other eva@mala.sk")
    a = engine.analyze("\n".join(lines))
    assert a.kind == "log" and a.model_complete
    assert a.stats["unique_templates"] <= 3
    out = render(a).split("\n")
    assert out[0].endswith("user=[PERSON_1]") and out[499].endswith("user=[PERSON_1]")
    assert out[500] == "mail [EMAIL_1] and again [EMAIL_1], other [EMAIL_2]"


def test_loki_json_only_redacts_lines(engine):
    loki = {"status": "success", "data": {"resultType": "streams", "result": [
        {"stream": {"namespace": "shop", "user": "Ján Novák"},
         "values": [["1", "login Ján Novák from 85.237.1.2"], ["2", "GET /health 200"]]}]}}
    a = engine.analyze(json.dumps(loki))
    assert a.kind == "loki_json"
    out = json.loads(render(a))
    vals = out["data"]["result"][0]["values"]
    assert vals[0][1] == "login [PERSON_1] from [IP_ADDRESS_1]"
    assert vals[1][1] == "GET /health 200"
    assert out["data"]["result"][0]["stream"]["user"] == "Ján Novák"  # labels untouched


def test_generic_json_with_nested_json_string(engine):
    inner = json.dumps({"msg": "user Ján Novák logged in"})
    obj = [{"type": "text", "text": inner}]
    a = engine.analyze(json.dumps(obj))
    out = json.loads(render(a))
    assert json.loads(out[0]["text"])["msg"] == "user [PERSON_1] logged in"


def test_auto_approve_when_nothing_found(engine, store):
    a = engine.analyze("GET /health 200\nGET /ready 200\nGET /metrics 200")
    r = store.submit(a, "test", "kubectl logs x")
    assert r.status == "auto_approved"
    assert r.output == "GET /health 200\nGET /ready 200\nGET /metrics 200"
    rec = json.loads(review_mod.AUDIT_PATH.read_text().splitlines()[-1])
    assert rec["decision"] == "auto_approved"


def test_no_auto_approve_when_model_incomplete(engine, store):
    a = engine.analyze("nothing here")
    a.model_complete = False
    assert store.submit(a, "test", "").status == "pending"


def test_review_edits_and_audit_has_no_content(engine, store):
    text = "Ján Novák wrote from jan@novak.sk about invoice 7781"
    a = engine.analyze(text)
    r = store.submit(a, "test", "cat x.log")
    assert r.status == "pending"
    labels = {s.label: i for i, s in enumerate(a.spans)}
    inv = text.index("7781")
    r = store.decide(r.id, "approve", disabled=[labels["EMAIL"]], added=[(inv, inv + 4)], note="")
    assert r.status == "approved"
    assert r.output == "[PERSON_1] wrote from jan@novak.sk about invoice [MANUAL_1]"
    audit = review_mod.AUDIT_PATH.read_text()
    assert "Novák" not in audit and "novak.sk" not in audit and "7781" not in audit
    assert r.analysis.doc_text == ""  # original dropped after decision


def test_reject(engine, store):
    r = store.submit(engine.analyze("hi Ján Novák"), "test", "")
    r = store.decide(r.id, "reject", [], [], note="too sensitive")
    assert r.status == "rejected" and r.output is None and r.note == "too sensitive"
