# Local build of philter-mcp

Vendored from https://github.com/philterd/philter-mcp at commit f75801f (2026-10-19),
with two fixes for Philter 4.x (diff: `local-fixes.patch`):

1. `status` tool: calls `GET /api/health` (Philter 4.x removed `/api/status`; falls back to it on 404).
2. `redact_text` / `redact_file`: a `context` that doesn't exist yet is created
   (`POST /api/contexts`) on first use instead of failing with HTTP 400.

To drop this copy once upstream fixes both: switch `philter-mcp` in ../docker-compose.yaml
back to `image: philterd/philter-mcp:latest` and remove `build:`.
