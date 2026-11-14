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
wait_for https://localhost:8080/api/health "Philter (can take a minute on Apple Silicon)"
wait_for http://localhost:8000/health      "philter-mcp"

echo "Uploading policy…"
./sync-policy.sh

if command -v claude >/dev/null; then
  if claude mcp get philter >/dev/null 2>&1; then
    echo "Claude Code already has the philter MCP server."
  else
    claude mcp add --transport http --scope user philter http://localhost:8000/mcp
    echo "Added the philter MCP server to Claude Code (user scope)."
  fi
else
  echo "Claude Code not found. Later, run:"
  echo "  claude mcp add --transport http --scope user philter http://localhost:8000/mcp"
fi

cat <<'EOF'

Setup complete. Last step, in a Claude Code session:

  /plugin install philter-scrub --marketplace roberthallatt999/philter-guard

Then check it with:  /scrub
EOF
