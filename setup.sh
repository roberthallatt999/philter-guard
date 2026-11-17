#!/usr/bin/env bash
# One-time setup on a new computer:
#   1. creates .env with fresh keys (if there isn't one)
#   2. starts Philter + philter-mcp in Docker
#   3. uploads the redaction policy
#   4. registers the Philter MCP server with Claude Code
# Safe to re-run: existing keys and data are kept.
set -euo pipefail
cd "$(dirname "$0")"

need() { command -v "$1" >/dev/null || { echo "Missing: $1. $2"; exit 1; }; }
need docker  "Install Docker Desktop or OrbStack first."
need jq      "Install it with: brew install jq"
need openssl "It ships with macOS; on Linux install openssl."
need curl    ""

if [[ ! -f .env ]]; then
  echo "Creating .env with new keys…"
  ( umask 077
    { echo "PHILTER_ENCRYPTION_KEY=$(openssl rand -base64 32)"
      echo "PHILTER_BOOTSTRAP_API_KEY=sk_$(openssl rand -hex 16)"; } > .env )
  echo "  Done. Back up .env somewhere safe (a password manager): Philter's data can't be read without it."
else
  echo "Keeping existing .env."
fi

set -a; . ./.env; set +a
mcp_url="http://127.0.0.1:${PHILTER_MCP_HOST_PORT:-18000}/mcp"
api_url="https://127.0.0.1:${PHILTER_API_HOST_PORT:-18443}"

echo "Starting containers…"
docker compose up -d

wait_for() { # url, label
  printf "Waiting for %s" "$2"
  for _ in $(seq 1 90); do
    curl -skf -o /dev/null "$1" && { echo " ✓"; return 0; }
    printf "."; sleep 2
  done
  echo; echo "$2 didn't come up. Check: docker compose logs"; exit 1
}
wait_for "$api_url/api/health" "Philter (can take a minute on Apple Silicon)"
wait_for "${mcp_url%/mcp}/health" "philter-mcp"

echo "Uploading policy…"
./sync-policy.sh

if command -v claude >/dev/null; then
  current=$(claude mcp get philter 2>/dev/null </dev/null || true)
  if [[ "$current" == *"$mcp_url"* ]]; then
    echo "Claude Code already has the philter MCP server at $mcp_url."
  else
    [[ -n "$current" ]] && claude mcp remove --scope user philter </dev/null >/dev/null 2>&1 || true
    claude mcp add --transport http --scope user philter "$mcp_url" </dev/null
    echo "Registered the philter MCP server with Claude Code at $mcp_url (user scope)."
  fi
else
  echo "Claude Code not found. Later, run:"
  echo "  claude mcp add --transport http --scope user philter $mcp_url"
fi

cat <<'EOF'

Setup complete. Last step, in a Claude Code session:

  /plugin install philter-scrub --marketplace roberthallatt999/philter-guard

Then check it with:  /scrub
EOF
