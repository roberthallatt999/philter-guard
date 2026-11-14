#!/usr/bin/env bash
# Builds one Philter policy per client set, then uploads them. Inputs:
#   policies/comprehensive.json   the base (all built-in filters + Canadian patterns)
#   library/*.json                reusable pieces, each adding "identifiers" (regex)
#                                 and/or "dictionaries" (word lists)
#   sets/<name>.json              one per client: { "include": ["piece", ...] }
# Output: policy "comprehensive" (base + library/api-keys.json) and one policy "set-<name>"
# per set file (base + library/api-keys.json + the set's pieces). api-keys is in every policy; no set
# can opt out. Philter uses the new versions on the next request; no restart needed.
#
#   ./sync-policy.sh                  validate, build, show a summary, upload
#   ./sync-policy.sh --dry-run        validate, build and show the summary only
#   ./sync-policy.sh --root DIR       read policies/, library/ and sets/ under DIR
#   ./sync-policy.sh --out DIR        write DIR/comprehensive.json, DIR/set-<name>.json; upload nothing
# Any validation error exits 1 with nothing written or uploaded.
set -euo pipefail
shopt -s nullglob

root="$(cd "$(dirname "$0")" && pwd)"
dry_run=0
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) dry_run=1 ;;
    --root) root="${2:?--root needs a folder}"; shift ;;
    --out)  out="${2:?--out needs a folder}"; shift ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

base="$root/policies/comprehensive.json"
always="api-keys"   # merged into every policy
errors=()
err() { errors+=("$1"); }

# ---- Validate everything first ----
[[ -f "$base" ]] && { jq -e . "$base" >/dev/null 2>&1 || err "policies/comprehensive.json is not valid JSON"; } \
  || err "policies/comprehensive.json not found"
[[ -f "$root/library/$always.json" ]] || err "library/$always.json not found"

pieces=()
for f in "$root"/library/*.json; do
  name=$(basename "$f" .json)
  jq -e 'type == "object"' "$f" >/dev/null 2>&1 || { err "library/$name.json is not a valid JSON object"; continue; }
  pieces+=("$name")
done

sets=()
for f in "$root"/sets/*.json; do
  name=$(basename "$f" .json)
  if [[ ! "$name" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
    err "sets/$name.json: set names use lowercase letters, digits and hyphens"; continue
  fi
  if [[ "$name" == "comprehensive" ]]; then
    err "sets/comprehensive.json: 'comprehensive' is reserved for the base policy"; continue
  fi
  if ! jq -e '(.include // []) | type == "array" and all(type == "string")' "$f" >/dev/null 2>&1; then
    err "sets/$name.json: not valid JSON, or \"include\" is not a list of piece names"; continue
  fi
  while IFS= read -r piece; do
    [[ -f "$root/library/$piece.json" ]] || err "sets/$name.json: includes '$piece' but library/$piece.json does not exist"
  done < <(jq -r '(.include // [])[]' "$f")
  sets+=("$name")
done

if [[ ${#errors[@]} -gt 0 ]]; then
  printf 'Error: %s\n' "${errors[@]}" >&2
  exit 1
fi

# ---- Build every policy into a temp dir ----
built=$(mktemp -d)
trap 'rm -rf "$built"' EXIT

# Merge: piece identifiers/dictionaries are appended to the base arrays. Top-level keys
# starting with "_" (_about, _tests) are notes for people and never reach Philter.
merge() { # output file, piece names...
  local dest="$1"; shift
  local files=() p
  for p in "$@"; do files+=("$root/library/$p.json"); done
  jq -s '
    def clean: with_entries(select(.key | startswith("_") | not));
    (.[0] | clean) as $base | [.[1:][] | clean] as $pieces
    | $base
    | .identifiers.identifiers  += ([$pieces[] | .identifiers  // [] | .[]])
    | .identifiers.dictionaries += ([$pieces[] | .dictionaries // [] | .[]])
  ' "$base" "${files[@]}" > "$dest"
}

merge "$built/comprehensive.json" "$always"
for s in ${sets[@]+"${sets[@]}"}; do
  list=()
  while IFS= read -r piece; do
    [[ "$piece" == "$always" ]] || list+=("$piece")
  done < <(jq -r '(.include // []) | reduce .[] as $x ([]; if index($x) then . else . + [$x] end) | .[]' "$root/sets/$s.json")
  merge "$built/set-$s.json" "$always" ${list[@]+"${list[@]}"}
done

# Server-side policy names: the base, and each set uploaded as set-<name>. A repo can
# only select a "set-" policy, and every one of them is built from the base.
names=(comprehensive)
for s in ${sets[@]+"${sets[@]}"}; do names+=("set-$s"); done
echo "Library pieces: ${pieces[*]:-none}"
for n in "${names[@]}"; do
  printf '%-16s %s built-in filters, %s custom patterns, %s word lists\n' "$n:" \
    "$(jq '[.identifiers | keys[] | select(. != "identifiers" and . != "dictionaries")] | length' "$built/$n.json")" \
    "$(jq '.identifiers.identifiers | length' "$built/$n.json")" \
    "$(jq '.identifiers.dictionaries | length' "$built/$n.json")"
done

if [[ -n "$out" ]]; then
  mkdir -p "$out"
  for n in "${names[@]}"; do cp "$built/$n.json" "$out/$n.json"; done
  echo "(wrote ${#names[@]} policies to $out, nothing uploaded)"
  exit 0
fi
[[ $dry_run -eq 1 ]] && { echo "(dry run, nothing uploaded)"; exit 0; }

# ---- Upload ----
set -a; . "$root/.env"; set +a
api="https://localhost:8080/api/policies"
send() { # method, url, file
  curl -sk -o /dev/stderr -w '%{http_code}' -X "$1" "$2" \
    -H "Authorization: Bearer $PHILTER_BOOTSTRAP_API_KEY" \
    -H "Content-Type: application/json" --data-binary @"$3"
}
uploaded=(); failed=()
for n in "${names[@]}"; do
  code=$(send PUT "$api/$n" "$built/$n.json" || true)
  if [[ "$code" == "404" ]]; then   # first run on this computer: create it
    code=$(send POST "$api?name=$n" "$built/$n.json" || true)
  fi
  echo
  if [[ "$code" == "200" || "$code" == "201" ]]; then
    uploaded+=("$n")
  else
    echo "Upload of $n failed (HTTP $code)." >&2
    failed+=("$n")
  fi
done

# Report policies on the server that no longer have a set (never deleted automatically).
# The listing is an object that nests the names array (e.g. {policies: {policies: [...]}}),
# items being strings or {name}; look for the first array up to 4 levels down. Philter's
# built-in "default" is not ours and is left out.
parse_names='
  def firstarr($d): if type == "array" then .
    elif $d >= 4 or type != "object" then null
    else ([.[] | firstarr($d + 1)] | map(select(. != null)) | first) end;
  (firstarr(0)) as $a
  | if $a == null then error("no list of policies found") else $a[] end
  | (if type == "object" then .name else . end) | strings | select(. != "default")'
stale=()
if listing=$(curl -sk -f "$api" -H "Authorization: Bearer $PHILTER_BOOTSTRAP_API_KEY") \
   && existing=$(jq -r "$parse_names" <<<"$listing"); then
  while IFS= read -r n; do
    [[ -z "$n" ]] && continue
    keep=0; for k in "${names[@]}"; do [[ "$n" == "$k" ]] && keep=1; done
    [[ $keep -eq 0 ]] && stale+=("$n")
  done <<<"$existing"
  selectable=(); other=()
  for n in ${stale[@]+"${stale[@]}"}; do
    if [[ "$n" == set-* ]]; then selectable+=("$n"); else other+=("$n"); fi
  done
  [[ ${#selectable[@]} -gt 0 ]] && echo "Stale (not deleted, still selectable by .philter): ${selectable[*]}"
  [[ ${#other[@]} -gt 0 ]] && echo "Stale (not deleted): ${other[*]}"
else
  echo "Warning: could not fetch or read the policy list from Philter, so stale policies were not checked." >&2
fi

echo "Uploaded: ${uploaded[*]:-none}"
if [[ ${#failed[@]} -gt 0 ]]; then
  echo "Failed:   ${failed[*]}"
  exit 1
fi
