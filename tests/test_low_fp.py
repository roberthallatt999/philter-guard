#!/usr/bin/env python3
"""Checks the low-false-positive proposal against tests/cases/low_fp_corpus.py.

Run:  python3 tests/test_low_fp.py            # the live rules: policies/ and library/ in this repo
      python3 tests/test_low_fp.py --proposed # the rules in docs/proposals/low-fp/proposed.py

Like test_patterns.py this uses Python's regex engine as a stand-in for Java's, and prints
case numbers, never fake secret values. Built-in filters (names, phones, IPs) can't run here:
their ignoredPatterns are checked on the spans Philter produced, and the phone/name
thresholds on the confidences it reported. After a sync, confirm with explain_redactions.
"""
import importlib.util
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROPOSED = "--proposed" in sys.argv
CURRENT = not PROPOSED


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P = load(ROOT / "docs" / "proposals" / "low-fp" / "proposed.py", "proposed")
C = load(ROOT / "tests" / "cases" / "low_fp_corpus.py", "low_fp_corpus")

library = json.loads((ROOT / "library" / "api-keys.json").read_text())["identifiers"]
if CURRENT:
    secret_rules = library
    base = json.loads((ROOT / "policies" / "comprehensive.json").read_text())
    ids = base["identifiers"]
    version = next(p["pattern"] for p in base["ignoredPatterns"] if p["name"] == "version-numbers")
    # Filter-level ignoredPatterns plus the policy-level ones (Phileas applies both to a span).
    policy_level = [p["pattern"] for p in base["ignoredPatterns"]]
    span_ignores = {f: [p["pattern"] for p in ids.get(f, {}).get("ignoredPatterns", [])] + policy_level
                    for f in ("ipAddress", "person")}
    # Policy-level "ignored" holds {name, terms} groups; a filter's own is a plain list of terms.
    terms = {"person": {t.lower() for g in base.get("ignored", []) for t in g["terms"]}
             | {t.lower() for t in ids["person"].get("ignored", [])}}
    person_threshold = ids["person"]["phEyeConfiguration"]["threshold"]
    conds = [st.get("condition", "") for st in ids["phoneNumber"]["phoneNumberFilterStrategies"]]
    m = re.fullmatch(r"confidence > ([0-9.]+)", conds[0]) if conds and conds[0] else None
    phone_threshold = float(m.group(1)) if m else 0.0
else:
    replaced = {"secret-labelled-value", "secret-jwt", "secret-npm-auth"}
    secret_rules = [r for r in library if r["classification"] not in replaced] + P.LABELLED + [P.JWT, P.NPM_AUTH]
    version = P.VERSION_NUMBERS
    span_ignores = {"ipAddress": P.IP_IGNORED, "person": P.PERSON_IGNORED}
    terms = {"person": {t.lower() for t in P.TOOL_WORDS}}


def finds(rules, text, cls=None):
    out = []
    for r in rules:
        if cls and r["classification"] != cls:
            continue
        flags = 0 if r.get("caseSensitive", True) else re.I
        g = r.get("groupNumber", 0)
        out += [(r["classification"], m.group(g)) for m in re.finditer(r["pattern"], text, flags)]
    return out


failed = total = 0


def check(ok, label):
    global failed, total
    total += 1
    if not ok:
        failed += 1
        print("FAIL", label)


for i, (cls, text, want) in enumerate(C.SECRET_TP):
    got = [v for _, v in finds(secret_rules, text, cls)]
    check(want in got, f"secret TP {i} ({cls}) not caught exactly")

for i, text in enumerate(C.SECRET_FP):
    hits = finds(secret_rules, text)
    check(not hits, f"secret FP line {i} matched {sorted({c for c, _ in hits})}")

for i, (flt, span, must_ignore) in enumerate(C.SPAN_CASES):
    ignored = span.lower() in terms.get(flt, set()) or any(
        re.fullmatch(p, span) for p in span_ignores[flt])
    # spans are not secrets, so they may be printed
    check(ignored == must_ignore, f"span {i} {flt} {span!r}: {'should' if must_ignore else 'should not'} be ignored")

if PROPOSED:
    person_threshold = P.BUILTIN_OVERRIDES["person"]["phEyeConfiguration"]["threshold"]
    phone_threshold = 0.9
for i, (flt, span, conf, real) in enumerate(C.OBSERVED):
    kept = conf > phone_threshold if flt == "phoneNumber" else conf >= person_threshold
    if flt == "person" and not real:
        # below-threshold or ignored by pattern: either is fine
        kept = kept and not any(re.fullmatch(p, span) for p in span_ignores["person"]) \
            and span.lower() not in terms["person"]
    check(kept == real, f"observed {i} {flt} {span!r} conf {conf}: {'redacted' if kept else 'passed'}")

for i, (text, must) in enumerate(C.VERSION_CASES):
    check(bool(re.fullmatch(version, text)) == must, f"version {i} {text!r}")

# The existing api-keys cases, against the same rules: shows what the proposal gives up.
K = load(ROOT / "tests" / "cases" / "api_keys.py", "api_keys")
SECRET = {r["classification"] for r in secret_rules}
regressions = []
for i, (cls, text, want) in enumerate(K.CASES):
    if want is None:
        ok = not any(finds(secret_rules, text, c) for c in SECRET)
    else:
        ok = [v for _, v in finds(secret_rules, text, cls)] == [want]
    if not ok:
        regressions.append(f"api_keys case {i} ({cls}, {'must not match' if want is None else 'must catch'})")
print(f"api_keys.py cases: {len(K.CASES) - len(regressions)}/{len(K.CASES)} still pass")
for r in regressions:
    print("  CHANGED", r)

print(f"{'live' if CURRENT else 'proposed'} rules: {total - failed}/{total} passed")
sys.exit(1 if failed else 0)
