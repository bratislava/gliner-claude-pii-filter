"""Deterministic PII / secret detectors with checksum validation.

Each detector yields Span(start, end, label, source="regex", score=1.0).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, Iterator, List, Optional


@dataclass
class Span:
    start: int
    end: int
    label: str
    source: str = "regex"
    score: float = 1.0


# ---------------------------------------------------------------- validators

def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def iban_ok(raw: str) -> bool:
    s = re.sub(r"\s+", "", raw).upper()
    if not 15 <= len(s) <= 34:
        return False
    s = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in s)
    return int(num) % 97 == 1


def rodne_cislo_ok(raw: str) -> bool:
    d = raw.replace("/", "")
    if not d.isdigit() or len(d) not in (9, 10):
        return False
    month = int(d[2:4])
    day = int(d[4:6])
    if month > 70:
        month -= 70
    elif month > 50:
        month -= 50
    elif month > 20:
        month -= 20
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return False
    if len(d) == 9:  # pre-1954 numbers have no checksum; require the slash
        return "/" in raw
    n = int(d)
    if n % 11 == 0:
        return True
    return int(d[:9]) % 11 == 10 and d[9] == "0"


_ACC_W = [6, 3, 7, 9, 10, 5, 8, 4, 2, 1]


def _mod11_weighted(num: str, width: int) -> bool:
    num = num.zfill(width)
    weights = _ACC_W[-width:]
    return sum(int(c) * w for c, w in zip(num, weights)) % 11 == 0


def sk_account_ok(m: re.Match) -> bool:
    prefix, number = m.group("pre"), m.group("num")
    if prefix and not _mod11_weighted(prefix, 6):
        return False
    if int(number) == 0:
        return False
    return _mod11_weighted(number, 10)


def ico_ok(raw: str) -> bool:
    if len(raw) != 8 or not raw.isdigit():
        return False
    s = sum(int(raw[i]) * (8 - i) for i in range(7))
    c = (11 - s % 11) % 10
    return c == int(raw[7])


def public_ip(raw: str) -> bool:
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified
                or ip.is_multicast or ip.is_reserved
                or (ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10")))


# ---------------------------------------------------------------- detectors

@dataclass
class Detector:
    label: str
    pattern: re.Pattern
    group: int | str = 0
    validate: Optional[Callable[[re.Match], bool]] = None


def _v(fn: Callable[[str], bool], group: int | str = 0) -> Callable[[re.Match], bool]:
    return lambda m: fn(m.group(group))


SECRET_KEYS = (r"password|passwd|pwd|pass|heslo|secret|client[_-]?secret|token|access[_-]?token|"
               r"refresh[_-]?token|id[_-]?token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|"
               r"authorization|x-api-key|session[_-]?id|cookie|set-cookie")

DETECTORS: List[Detector] = [
    Detector("PRIVATE_KEY", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    Detector("JWT", re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}")),
    Detector("SECRET", re.compile(r"(?i)\bbearer\s+(?P<v>[A-Za-z0-9._~+/-]{8,}=*)"), "v"),
    Detector("SECRET", re.compile(r"(?i)\bbasic\s+(?P<v>[A-Za-z0-9+/]{8,}=*)"), "v"),
    Detector("SECRET", re.compile(
        r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_\w{20,}|glpat-[\w-]{20,}"
        r"|xox[abprs]-[\w-]{10,}|sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35})")),
    Detector("SECRET", re.compile(r"(?<=://)(?P<v>[^/\s:@]+:[^/\s@]+)(?=@)"), "v"),
    Detector("SECRET", re.compile(
        r"(?i)(?<![\w-])[\"']?(?:" + SECRET_KEYS + r")[\"']?\s*[:=]\s*[\"']?"
        r"(?P<v>(?!(?i:null|true|false|bearer|basic)\b|\*+[\"',;\s}]|\[)[^\s\"',;&}]{3,})"), "v"),
    Detector("EMAIL", re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}")),
    Detector("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b"),
             validate=_v(iban_ok)),
    Detector("NATIONAL_ID", re.compile(r"(?<![\w/.-])\d{6}/?\d{3,4}(?![\w/.-])"),
             validate=_v(rodne_cislo_ok)),
    Detector("BANK_ACCOUNT", re.compile(
        r"(?<![\w/-])(?:(?P<pre>\d{1,6})-)?(?P<num>\d{2,10})/(?P<bank>\d{4})(?![\w/])"),
        validate=sk_account_ok),
    Detector("COMPANY_ID", re.compile(r"(?i)\b(?:IČO|ICO|IČ|company_?id)\b\W{0,4}(?P<v>\d{8})\b"), "v",
             validate=_v(ico_ok, "v")),
    Detector("TAX_ID", re.compile(r"(?i)\b(?:DIČ|DIC)\b\W{0,4}(?P<v>\d{10})\b"), "v"),
    Detector("TAX_ID", re.compile(r"\b(?:SK|CZ)\d{8,10}\b")),
    Detector("PHONE", re.compile(
        r"(?<![\w+])(?:\+|00)(?:421|420)[ -]?\d{3}[ -]?\d{3}[ -]?\d{3}(?!\w)")),
    Detector("PHONE", re.compile(r"(?<![\w+])0(?:9\d{2})[ -]?\d{3}[ -]?\d{3}(?!\w)")),
    Detector("PHONE", re.compile(r"(?<![\w/+.-])0[2-5]\d?(?:/ ?| )\d{3} ?\d{2} ?\d{2,3}(?![\d/])")),
    Detector("PHONE", re.compile(r"(?<![\w+])\+(?!42[01])\d{1,3}(?:[ -]?\d){8,12}(?!\w)")),
    Detector("CARD_NUMBER", re.compile(r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])"),
             validate=lambda m: luhn_ok(re.sub(r"\D", "", m.group(0)))
             and len(re.sub(r"\D", "", m.group(0))) in (13, 14, 15, 16, 19)
             and re.sub(r"\D", "", m.group(0))[0] in "2345"),
    Detector("IP_ADDRESS", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
             validate=_v(public_ip)),
    Detector("IP_ADDRESS", re.compile(
        r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}(?![\w:])"),
        validate=_v(public_ip)),
]


def find_regex_spans(text: str) -> List[Span]:
    spans: List[Span] = []
    for det in DETECTORS:
        for m in det.pattern.finditer(text):
            if det.validate and not det.validate(m):
                continue
            s, e = m.span(det.group)
            if e > s:
                spans.append(Span(s, e, det.label))
    return spans


def iter_labels() -> Iterator[str]:
    seen = set()
    for d in DETECTORS:
        if d.label not in seen:
            seen.add(d.label)
            yield d.label
