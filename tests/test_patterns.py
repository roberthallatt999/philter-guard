#!/usr/bin/env python3
"""Regression tests for the custom regex patterns in the policy.

Run:  python3 tests/test_patterns.py
Python's regex engine is close enough to Java's for these patterns. Philter itself
is the final word: after a sync, check with the philter redact_text tool.
"""
import importlib.util
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
POLICY = ROOT / "policies" / "comprehensive.json"
# The base plus every library piece, since each piece's patterns end up in a built policy.
patterns = json.loads(POLICY.read_text())["identifiers"]["identifiers"]
for piece in sorted((ROOT / "library").glob("*.json")):
    patterns += json.loads(piece.read_text()).get("identifiers", [])


def matches(classification: str, text: str) -> list[str]:
    found = []
    for p in patterns:
        if p["classification"] != classification:
            continue
        flags = 0 if p.get("caseSensitive", True) else re.I
        group = p.get("groupNumber", 0)
        found += [m.group(group) for m in re.finditer(p["pattern"], text, flags)]
    return found


# (classification, text, the substring that must be caught, or None for "must not match")
CASES = [
    # passports
    ("passport-number", "Her passport number is 123456789.", "123456789"),
    ("passport-number", "Passport No. 123456789", "123456789"),
    ("passport-number", "Travel document no. 123456789", "123456789"),
    ("passport-number", "Passport: GA302922", "GA302922"),
    ("passport-number", "passeport no AB 123456", "AB 123456"),
    ("passport-number", "Reisepass/passport C01X00T47", "C01X00T47"),
    ("passport-number", "Doc A12345678 on file", "A12345678"),
    ("passport-number", "Canadian AB123456", "AB123456"),
    ("passport-number", "request_id=1731580937 build 15558508", None),
    ("passport-number", "the passport office is closed", None),
    # health cards
    ("health-card-number", "OHIP 1234-567-890-AB", "1234-567-890-AB"),
    ("health-card-number", "RAMQ TREM 7503 1412", "TREM 7503 1412"),
    ("health-card-number", "AHCIP 12345-6789", "12345-6789"),
    ("health-card-number", "epoch 1731580937 in a log", None),
    # postal / ZIP
    ("postal-code", "Toronto ON M5V 3L9", "M5V 3L9"),
    ("postal-code", "h2x1y4", "h2x1y4"),
    ("us-zip-code", "Beverly Hills, CA 90210", "90210"),
    ("us-zip-code", "line 48213 of worker.log", None),
    # licences, business, bank, MRN
    ("drivers-licence", "DL A1234-56789-01234", "A1234-56789-01234"),
    ("drivers-licence", "bundled dependencies", None),
    ("business-number", "BN 123456789RT0001", "123456789RT0001"),
    ("bank-account", "transit 12345-003-1234567", "12345-003-1234567"),
    ("medical-record-number", "MRN: AB-55321", "AB-55321"),
    # facilities
    ("health-facility", "seen at Toronto General Hospital", "Toronto General Hospital"),
    ("health-facility", "the Hospital for Sick Children and Centre for Addiction and Mental Health",
     "Centre for Addiction and Mental Health"),
]

# Per-piece cases: tests/cases/<piece>.py (hyphens become underscores) exports CASES, the
# same tuples as above. Piece cases build fake credentials at runtime, so a failing line
# prints only the piece, classification and case number, never the value.
ALL = [("base", c) for c in CASES]
for f in sorted((ROOT / "tests" / "cases").glob("*.py")):
    spec = importlib.util.spec_from_file_location(f.stem, f)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    ALL += [(f.stem, c) for c in mod.CASES]


def caught(want, got):
    return any(want in g or g in want and len(g) >= len(want) - 1 for g in got)


SECRET = {p["classification"] for p in patterns if p["classification"].startswith("secret-")}

failed = 0
for i, (source, (cls, text, want)) in enumerate(ALL):
    got = matches(cls, text)
    ok = (not got) if want is None else caught(want, got)
    if ok and want is None and source != "base":
        # a piece's "must not match" case holds for every secret- classification
        ok = not any(matches(c, text) for c in SECRET)
    if not ok:
        failed += 1
        if source == "base":
            print(f"FAIL {cls}: {text!r} -> {got!r} (wanted {want!r})")
        else:
            print(f"FAIL [{source}] {cls} case {i}: {'must not match' if want is None else 'must catch'}")
CASES = [c for _, c in ALL]
print(f"{len(CASES) - failed}/{len(CASES)} passed")
sys.exit(1 if failed else 0)
