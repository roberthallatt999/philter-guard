#!/usr/bin/env bash
# Builds the live "comprehensive" Philter policy from:
#   policies/comprehensive.json   the base (all built-in filters + Canadian patterns)
#   projects/*.json               one file per project, each adding its own
#                                 "identifiers" (regex) and/or "dictionaries" (word lists)
# then uploads it. Philter uses the new version on the next request; no restart needed.
#
#   ./sync-policy.sh            build, show a summary, upload
#   ./sync-policy.sh --dry-run  build and show the summary only
set -euo pipefail
cd "$(dirname "$0")"

built=$(mktemp)
trap 'rm -f "$built"' EXIT

# Merge: project identifiers/dictionaries are appended to the base arrays.
jq -s '
  .[0] as $base | .[1:] as $projects
  | $base
  | .identifiers.identifiers  += ([$projects[] | .identifiers  // [] | .[]])
  | .identifiers.dictionaries += ([$projects[] | .dictionaries // [] | .[]])
' policies/comprehensive.json projects/*.json 2>/dev/null > "$built" \
  || jq '.' policies/comprehensive.json > "$built"   # no project files yet

echo "Projects: $(ls projects/*.json 2>/dev/null | xargs -n1 basename 2>/dev/null | sed 's/\.json$//' | paste -sd, - || true)"
echo "Built-in filters: $(jq '[.identifiers | keys[] | select(. != "identifiers" and . != "dictionaries")] | length' "$built")"
echo "Custom patterns:  $(jq '.identifiers.identifiers | length' "$built")"
echo "Word lists:       $(jq '.identifiers.dictionaries | length' "$built")"

[[ "${1:-}" == "--dry-run" ]] && { echo "(dry run, nothing uploaded)"; exit 0; }

set -a; . ./.env; set +a
send() { # method, url
  curl -sk -o /dev/stderr -w '%{http_code}' -X "$1" "$2" \
    -H "Authorization: Bearer $PHILTER_BOOTSTRAP_API_KEY" \
    -H "Content-Type: application/json" --data-binary @"$built"
}
code=$(send PUT "https://localhost:8080/api/policies/comprehensive")
if [[ "$code" == "404" ]]; then   # first run on this computer: create it
  code=$(send POST "https://localhost:8080/api/policies?name=comprehensive")
fi
echo
[[ "$code" == "200" || "$code" == "201" ]] && echo "Uploaded (HTTP $code)." || { echo "Upload failed (HTTP $code)."; exit 1; }
