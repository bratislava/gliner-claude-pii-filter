import pytest

from pii_filter.regexes import find_regex_spans, iban_ok, ico_ok, luhn_ok, rodne_cislo_ok


def labels(text):
    return {(s.label, text[s.start:s.end]) for s in find_regex_spans(text)}


@pytest.mark.parametrize("rc,ok", [
    ("9001011239", True),      # mod 11 == 0
    ("900101/1239", True),
    ("9053156783", True),      # female (month + 50)
    ("7801233540", True),      # legacy rule: first 9 digits mod 11 == 10, check digit 0
    ("9001011234", False),     # bad checksum
    ("8551017328", False),     # bad checksum
    ("9013011239", False),     # month 13
    ("900101/123", True),      # pre-1954 9-digit, slash required
    ("900101123", False),      # 9 digits without slash
])
def test_rodne_cislo(rc, ok):
    assert rodne_cislo_ok(rc) is ok


def test_iban():
    assert iban_ok("SK3112000000198742637541")
    assert iban_ok("SK31 1200 0000 1987 4263 7541")
    assert not iban_ok("SK3112000000198742637542")


def test_ico_luhn():
    assert ico_ok("00603481")      # Hlavné mesto SR Bratislava
    assert not ico_ok("00603482")
    assert luhn_ok("4111111111111111")
    assert not luhn_ok("4111111111111112")


def test_detects_slovak_identifiers():
    t = ("RČ 736028/5163, IČO: 00603481, DIČ 2020372596, IČ DPH SK2020372596, "
         "IBAN SK31 1200 0000 1987 4263 7541, účet 000019-2000145399/0800, "
         "tel +421 905 123 456 alebo 0905 123 456 alebo 02/593 56 111")
    got = labels(t)
    assert ("NATIONAL_ID", "736028/5163") in got
    assert ("COMPANY_ID", "00603481") in got
    assert ("TAX_ID", "2020372596") in got
    assert ("TAX_ID", "SK2020372596") in got
    assert ("IBAN", "SK31 1200 0000 1987 4263 7541") in got
    assert ("BANK_ACCOUNT", "000019-2000145399/0800") in got
    assert ("PHONE", "+421 905 123 456") in got
    assert ("PHONE", "0905 123 456") in got
    assert ("PHONE", "02/593 56 111") in got


def test_secrets_and_contacts():
    t = ('Authorization: Bearer abcdef123456.xyz password="hunter22" '
         'url=https://bob:s3cr3t@db.local/x token=ghp_' + "a" * 36 + ' mail jan@novak.sk '
         'jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U')
    got = labels(t)
    assert ("SECRET", "abcdef123456.xyz") in got
    assert ("SECRET", "hunter22") in got
    assert ("SECRET", "bob:s3cr3t") in got
    assert ("EMAIL", "jan@novak.sk") in got
    assert any(l == "JWT" for l, _ in got)


def test_ip_public_only():
    got = labels("from 10.2.3.4 and 192.168.1.1 and 85.237.1.2 and 127.0.0.1")
    assert got == {("IP_ADDRESS", "85.237.1.2")}


def test_no_false_positives_on_plain_log():
    t = ('{"ts":"2026-11-10T10:00:01Z","level":"info","msg":"request handled","path":"/api/v1/items/12345678",'
         '"status":200,"dur_ms":1234567,"trace":"4bf92f3577b34da6a3ce929d0e0e4736","pod":"api-7d9f8c-x2x"}')
    assert labels(t) == set()
