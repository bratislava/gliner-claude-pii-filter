"""Build a 'skeleton' of a text unit for the model.

Already-detected regex spans and high-entropy, non-personal tokens (log timestamps,
UUIDs, hex ids, small numbers) are replaced with fixed tokens. This (a) stops the model
from tagging timestamps as dates/tax ids and (b) makes repetitive log lines collapse to
identical skeletons so the model runs once per template.

Offsets of model spans found in the skeleton are mapped back to the original unit.
"""
from __future__ import annotations

import bisect
import re
from typing import List, Sequence, Tuple

from .regexes import Span

# Order matters: "keep" groups protect plain dates (possible dates of birth).
_MASK_RE = re.compile(
    r"(?P<keep>\b\d{1,2}\.\s?\d{1,2}\.\s?\d{4}\b|\b\d{4}-\d{2}-\d{2}\b(?![T ]\d{2}:\d{2}))"
    r"|(?P<TS>\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ \d]\d \d{2}:\d{2}:\d{2}\b"
    r"|\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b)"
    r"|(?P<UUID>\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b)"
    r"|(?P<HEX>\b(?=[0-9a-f]*[a-f])(?=[0-9a-f]*\d)[0-9a-f]{8,}\b)"
    r"|(?P<IP>(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?![\d.]))"
    r"|(?P<N>(?<=[/=:])\s?\"?\d{1,9}(?:\.\d+)?(?=[\s\",;&}/)\]]|$)|(?<=[/=:]\s\")\d{1,9}(?:\.\d+)?(?=\"))"
)
# values of technical id keys (trace=..., "request_id": "...", key=session:abc123)
_TECH_RE = re.compile(
    r"(?i)\b(?:trace|span|request|req|correlation|parent|txn|transaction|message|msg|event|job|task"
    r"|session|cache|etag|hash|sha|commit|nonce|key|id|uid|guid|pod|container|build|run)(?:[_-]?id)?"
    r"[\"']?\s*[:=]\s*[\"']?(?:[a-z]+:)?(?P<v>[0-9a-f][0-9a-f-]{5,}|\d{4,})(?![\w-])")

# in document mode small numbers are kept: they carry address / date context
_DOC_SKIP = {"N"}

Segment = Tuple[int, int, int, int, bool]  # skel_start, skel_end, orig_start, orig_end, is_mask


class Skeleton:
    __slots__ = ("text", "segments", "_starts")

    def __init__(self, text: str, segments: List[Segment]):
        self.text = text
        self.segments = segments
        self._starts = [s[0] for s in segments]

    def _seg(self, pos: int) -> Segment:
        i = bisect.bisect_right(self._starts, pos) - 1
        return self.segments[max(i, 0)]

    def to_orig(self, start: int, end: int) -> Tuple[int, int]:
        s0, _, o0, o1, mask = self._seg(start)
        ostart = o0 if mask else o0 + (start - s0)
        s0, _, o0, o1, mask = self._seg(max(end - 1, start))
        oend = o1 if mask else o0 + (end - s0)
        return ostart, oend


def build_skeleton(text: str, regex_spans: Sequence[Span], document: bool = False) -> Skeleton:
    # collect mask intervals: regex spans first, then structural tokens in the gaps
    masks: List[Tuple[int, int, str]] = [(s.start, s.end, f"[{s.label}]") for s in regex_spans]
    masks.sort()
    merged: List[Tuple[int, int, str]] = []
    for m in masks:
        if merged and m[0] < merged[-1][1]:
            last = merged[-1]
            merged[-1] = (last[0], max(last[1], m[1]), last[2])
        else:
            merged.append(m)

    def gaps():
        pos = 0
        for s, e, _ in merged:
            if s > pos:
                yield pos, s
            pos = max(pos, e)
        if pos < len(text):
            yield pos, len(text)

    structural: List[Tuple[int, int, str]] = []
    for gs, ge in list(gaps()):
        for m in _TECH_RE.finditer(text, gs, ge):
            structural.append((m.start("v"), m.end("v"), "ID"))
        for m in _MASK_RE.finditer(text, gs, ge):
            kind = m.lastgroup
            if kind == "keep" or (document and kind in _DOC_SKIP):
                continue
            structural.append((m.start(), m.end(), kind))
    # drop structural masks overlapping regex masks or each other (first/longest wins)
    taken = sorted(merged + sorted(structural, key=lambda x: (x[0], -(x[1] - x[0]))),
                   key=lambda x: x[0])
    merged = []
    for iv in taken:
        if merged and iv[0] < merged[-1][1]:
            continue
        merged.append(iv)

    out: List[str] = []
    segs: List[Segment] = []
    pos = 0
    spos = 0
    for s, e, tok in merged:
        if s > pos:
            lit = text[pos:s]
            segs.append((spos, spos + len(lit), pos, s, False))
            out.append(lit)
            spos += len(lit)
        segs.append((spos, spos + len(tok), s, e, True))
        out.append(tok)
        spos += len(tok)
        pos = e
    if pos < len(text) or not segs:
        lit = text[pos:]
        segs.append((spos, spos + len(lit), pos, len(text), False))
        out.append(lit)
    return Skeleton("".join(out), segs)
