#!/usr/bin/env bash
# Tests for sync-policy.sh's build step (never uploads, never reads the key file).
# Run:  bash tests/test_build.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(dirname "$here")"
fixture="$here/fixtures/build"
sync="$repo/sync-policy.sh"

pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  PASS  $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL  $1"; }
check() { # description, command...
  local d="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi
}
# count of entries with a classification in a built policy
count() { # file, classification
  jq --arg c "$2" '[.identifiers.identifiers[], .identifiers.dictionaries[] | select(.classification == $c)] | length' "$1"
}

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

echo "build from fixture"
out="$tmp/out"; mkdir "$out"
"$sync" --root "$fixture" --out "$out" >"$tmp/log" 2>&1; rc=$?
check "exits 0" test $rc -eq 0
check "comprehensive.json written" test -f "$out/comprehensive.json"
check "acme.json written" test -f "$out/acme.json"
check "other.json written" test -f "$out/other.json"
check "nothing written for the disabled template" test "$(ls "$out" | wc -l | tr -d ' ')" -eq 3
check "comprehensive has secret-fixture" test "$(count "$out/comprehensive.json" secret-fixture)" -eq 1
check "comprehensive has base-fixture" test "$(count "$out/comprehensive.json" base-fixture)" -eq 1
check "comprehensive has nothing from a" test "$(count "$out/comprehensive.json" a-fixture)" -eq 0
check "acme has a once" test "$(count "$out/acme.json" a-fixture)" -eq 1
check "acme has a's word list once" test "$(count "$out/acme.json" a-words)" -eq 1
check "acme has b once" test "$(count "$out/acme.json" b-fixture)" -eq 1
check "acme has secret-fixture" test "$(count "$out/acme.json" secret-fixture)" -eq 1
check "acme has base-fixture" test "$(count "$out/acme.json" base-fixture)" -eq 1
check "other has secret-fixture" test "$(count "$out/other.json" secret-fixture)" -eq 1
check "other has b" test "$(count "$out/other.json" b-fixture)" -eq 1
check "other has nothing from a" test "$(count "$out/other.json" a-fixture)" -eq 0
check "no built policy contains _tests" test "$(grep -l '_tests' "$out"/*.json | wc -l | tr -d ' ')" -eq 0
check "no built policy has _about" test "$(grep -l '_about' "$out"/*.json | wc -l | tr -d ' ')" -eq 0
check "built policies are valid JSON" jq -e . "$out/comprehensive.json" "$out/acme.json" "$out/other.json"

# expect_fail <description> <fixture-mutation shell snippet run in $copy> [message-regex]
expect_fail() {
  local d="$1" mutate="$2" msg="${3:-}"
  local copy="$tmp/copy"; rm -rf "$copy" "$tmp/o2"; cp -R "$fixture" "$copy"; mkdir "$tmp/o2"
  (cd "$copy" && eval "$mutate")
  local log; log=$("$sync" --root "$copy" --out "$tmp/o2" 2>&1); local rc=$?
  if [[ $rc -eq 1 ]]; then ok "$d: exits 1"; else bad "$d: exits 1 (got $rc)"; fi
  if [[ -z "$(ls -A "$tmp/o2")" ]]; then ok "$d: nothing written"; else bad "$d: nothing written"; fi
  if [[ -z "$msg" ]] || grep -q "$msg" <<<"$log"; then ok "$d: message"; else bad "$d: message names '$msg'"; fi
}

echo "validation errors"
expect_fail "missing include" 'echo "{\"include\":[\"missing\"]}" > sets/acme.json' missing
expect_fail "set named comprehensive" 'echo "{\"include\":[\"a\"]}" > sets/comprehensive.json' comprehensive
expect_fail "set named Bad_Name" 'echo "{\"include\":[\"a\"]}" > sets/Bad_Name.json' Bad_Name
expect_fail "invalid JSON piece" 'echo "{ nope" > library/a.json' a.json

echo "dry run"
log=$("$sync" --dry-run --root "$fixture" 2>&1); rc=$?
check "dry run exits 0" test $rc -eq 0
check "dry run lists comprehensive" grep -q 'comprehensive' <<<"$log"
check "dry run lists acme" grep -q 'acme' <<<"$log"
check "dry run lists other" grep -q 'other' <<<"$log"
check "dry run uploads nothing" grep -q 'nothing uploaded' <<<"$log"

echo
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
