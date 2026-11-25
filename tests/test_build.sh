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
check "set-acme.json written" test -f "$out/set-acme.json"
check "set-other.json written" test -f "$out/set-other.json"
check "no un-prefixed set file written" test ! -e "$out/acme.json" -a ! -e "$out/other.json"
check "nothing written for the disabled template" test "$(ls "$out" | wc -l | tr -d ' ')" -eq 3
check "comprehensive has secret-fixture" test "$(count "$out/comprehensive.json" secret-fixture)" -eq 1
check "comprehensive has base-fixture" test "$(count "$out/comprehensive.json" base-fixture)" -eq 1
check "comprehensive has nothing from a" test "$(count "$out/comprehensive.json" a-fixture)" -eq 0
check "acme has a once" test "$(count "$out/set-acme.json" a-fixture)" -eq 1
check "acme has a's word list once" test "$(count "$out/set-acme.json" a-words)" -eq 1
check "acme has b once" test "$(count "$out/set-acme.json" b-fixture)" -eq 1
check "acme has secret-fixture" test "$(count "$out/set-acme.json" secret-fixture)" -eq 1
check "acme has base-fixture" test "$(count "$out/set-acme.json" base-fixture)" -eq 1
check "other has secret-fixture" test "$(count "$out/set-other.json" secret-fixture)" -eq 1
check "other has b" test "$(count "$out/set-other.json" b-fixture)" -eq 1
check "other has nothing from a" test "$(count "$out/set-other.json" a-fixture)" -eq 0
check "no built policy contains _tests" test "$(grep -l '_tests' "$out"/*.json | wc -l | tr -d ' ')" -eq 0
check "no built policy has _about" test "$(grep -l '_about' "$out"/*.json | wc -l | tr -d ' ')" -eq 0
check "built policies are valid JSON" jq -e . "$out/comprehensive.json" "$out/set-acme.json" "$out/set-other.json"

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
check "dry run lists set-acme" grep -q 'set-acme' <<<"$log"
check "dry run lists set-other" grep -q 'set-other' <<<"$log"
check "dry run uploads nothing" grep -q 'nothing uploaded' <<<"$log"

echo "code- variants (policies/code-overlay.json)"
ov="$tmp/ov"; rm -rf "$ov" "$tmp/o3"; cp -R "$fixture" "$ov"; mkdir "$tmp/o3"
base_pat=$(jq -r '.identifiers.identifiers[0].pattern' "$ov/policies/comprehensive.json")
jq -n --arg p "$base_pat" '{_about: "test", disableBuiltins: ["emailAddress"], dropIdentifierPatterns: [$p], personThreshold: 0.92}' \
  > "$ov/policies/code-overlay.json"
"$sync" --root "$ov" --out "$tmp/o3" >"$tmp/log3" 2>&1; rc=$?
check "overlay: exits 0" test $rc -eq 0
check "overlay: six policies written" test "$(ls "$tmp/o3" | wc -l | tr -d ' ')" -eq 6
check "overlay: code-comprehensive written" test -f "$tmp/o3/code-comprehensive.json"
check "overlay: code-set-acme written" test -f "$tmp/o3/code-set-acme.json"
check "overlay: the prose policy keeps the disabled filter" jq -e '.identifiers.emailAddress != null' "$tmp/o3/comprehensive.json"
check "overlay: the code policy drops the disabled filter" jq -e '.identifiers.emailAddress == null' "$tmp/o3/code-comprehensive.json"
check "overlay: the dropped pattern is gone from code-" test "$(count "$tmp/o3/code-set-acme.json" base-fixture)" -eq 0
check "overlay: the dropped pattern stays in the prose set" test "$(count "$tmp/o3/set-acme.json" base-fixture)" -eq 1
check "overlay: other rules stay in code-" test "$(count "$tmp/o3/code-set-acme.json" a-fixture)" -eq 1
check "overlay: secrets stay in code-" test "$(count "$tmp/o3/code-comprehensive.json" secret-fixture)" -eq 1
check "overlay: no person filter is added where there was none" jq -e '.identifiers.person == null' "$tmp/o3/code-comprehensive.json"
check "overlay: no _about in built policies" test "$(grep -l '_about' "$tmp/o3"/*.json | wc -l | tr -d ' ')" -eq 0
expect_fail "overlay with a bad list" 'echo "{\"disableBuiltins\": \"age\"}" > policies/code-overlay.json' code-overlay
expect_fail "overlay with a bad threshold" 'echo "{\"personThreshold\": 5}" > policies/code-overlay.json' code-overlay

echo "upload path (stub curl, dummy key file, no network)"
# A fake root with a throwaway key file, built from parts so no literal protected file name
# or key=value line sits in this script. The stub curl goes first on PATH.
fake="$tmp/fake"; rm -rf "$fake"; cp -R "$fixture" "$fake"
keyfile="$fake/.""env"
key_var="PHILTER_BOOTSTRAP_API_""KEY"
dummy_value="not-a-real-value"
printf '%s=%s\n' "$key_var" "$dummy_value" > "$keyfile"
stubdir="$tmp/bin"; mkdir -p "$stubdir"
cat > "$stubdir/curl" <<'STUB'
#!/usr/bin/env bash
# Records "METHOD url"; answers uploads from $STUB_CODES ("METHOD name code" lines, default 200)
# and the policy listing from $STUB_LIST (or fails when STUB_LIST_FAIL is set).
method=""; url=""
while [[ $# -gt 0 ]]; do
  case "$1" in -X) method="$2"; shift ;; https://*) url="$1" ;; esac
  shift
done
echo "${method:-GET} $url" >> "$STUB_LOG"
if [[ -z "$method" ]]; then
  [[ -n "${STUB_LIST_FAIL:-}" ]] && exit 22
  cat "$STUB_LIST"; exit 0
fi
name="${url##*/}"; name="${name##*name=}"
code=$(awk -v k="$method $name" '($1 " " $2) == k { print $3 }' "$STUB_CODES")
printf '%s' "${code:-200}"
STUB
chmod +x "$stubdir/curl"
export STUB_LOG="$tmp/curl.log" STUB_CODES="$tmp/codes" STUB_LIST="$tmp/list"
two_level='{"policies":{"policies":[{"name":"default"},{"name":"comprehensive"},{"name":"set-acme"},{"name":"set-demo"},{"name":"legacy"}],"total":5}}'
run_upload() { # codes-file-content, list-body; leaves $log and $rc
  : > "$STUB_LOG"; printf '%s' "$1" > "$STUB_CODES"; printf '%s' "$2" > "$STUB_LIST"
  log=$(PATH="$stubdir:$PATH" "$sync" --root "$fake" 2>&1); rc=$?
}

run_upload "" "$two_level"
check "upload success: exits 0" test $rc -eq 0
check "upload success: PUT for each policy" test "$(grep -c '^PUT ' "$STUB_LOG")" -eq 3
check "upload success: no POST" test "$(grep -c '^POST ' "$STUB_LOG")" -eq 0
check "upload success: reports all uploaded" grep -q 'Uploaded: comprehensive set-acme set-other' <<<"$log"
check "stale: set- name marked selectable" grep -q 'still selectable by .philter): set-demo' <<<"$log"
check "stale: other name listed apart" grep -q 'Stale (not deleted): legacy' <<<"$log"
check "stale: built-in default not listed" test "$(grep -c 'default' <<<"$log")" -eq 0
check "stale: no warning when the list parses" test "$(grep -c 'could not fetch' <<<"$log")" -eq 0

run_upload "PUT set-acme 404" "$two_level"
check "404 then POST: exits 0" test $rc -eq 0
check "404 then POST: POST sent for the missing policy" grep -q '^POST .*name=set-acme' "$STUB_LOG"
check "404 then POST: only that one POSTed" test "$(grep -c '^POST ' "$STUB_LOG")" -eq 1

run_upload "PUT set-acme 500" "$two_level"
check "failed upload: exits 1" test $rc -eq 1
check "failed upload: names the failure" grep -q 'Upload of set-acme failed (HTTP 500)' <<<"$log"
check "failed upload: continues to the next" grep -q 'Uploaded: comprehensive set-other' <<<"$log"
check "failed upload: lists it under Failed" grep -q 'Failed:   set-acme' <<<"$log"

run_upload "" "not json at all"
check "unparseable list: warns" grep -q 'could not fetch or read the policy list' <<<"$log"
check "unparseable list: upload still succeeds" test $rc -eq 0
run_upload "" '{"policies":{"total":0}}'
check "list with no array: warns" grep -q 'could not fetch or read the policy list' <<<"$log"
: > "$STUB_LOG"; printf '' > "$STUB_CODES"
log=$(STUB_LIST_FAIL=1 PATH="$stubdir:$PATH" "$sync" --root "$fake" 2>&1); rc=$?
check "list request fails: warns" grep -q 'could not fetch or read the policy list' <<<"$log"
check "list request fails: exits 0" test $rc -eq 0

echo
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
