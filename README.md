# philter-guard

Keeps personal and customer data out of Claude Code sessions. A local [Philter](https://github.com/philterd/philter) server redacts it first, so names, emails, phone numbers, SINs, health card numbers, addresses and similar details reach Claude as placeholders like `{{{REDACTED-email-address}}}`.

It's built for coding work where programs sometimes print customer data: logs, command output, database query results and data files are scrubbed. Source code is left alone so Claude can still edit it.

## What's in here

| Path | What it is |
|---|---|
| `docker-compose.yaml` | Philter 4 and the philter-mcp server, bound to localhost only |
| `policies/comprehensive.json` | The base redaction policy: built-in filters, Canadian and US identifiers, and ignore rules for paths, versions and log timestamps |
| `projects/*.json` | Extra patterns and word lists for each project, merged into the policy |
| `sync-policy.sh` | Builds the policy from the base and project files and uploads it. Philter uses it from the next request, with no restart |
| `setup.sh` | One-time setup for a new computer |
| `plugins/philter-scrub/` | The Claude Code mod that sends prompts and tool output through Philter |

## Setting up a computer

You need Docker (Docker Desktop or OrbStack), `jq` (`brew install jq`) and Claude Code.

```bash
git clone https://github.com/roberthallatt999/philter-guard.git ~/docker/philter-mcp
cd ~/docker/philter-mcp
./setup.sh
```

`setup.sh` does four things:

1. Creates `.env` with new keys for this computer.
2. Starts the containers.
3. Uploads the policy.
4. Registers the `philter` MCP server with Claude Code.

Each computer has its own keys and doesn't share them with any other. **Back up `.env`**, for example in a password manager. Philter can't read its stored data without the encryption key.

<details><summary>Writing <code>.env</code> by hand</summary>

One `NAME=value` line per variable:

| Variable | Value |
|---|---|
| `PHILTER_ENCRYPTION_KEY` | The output of `openssl rand -base64 32` |
| `PHILTER_BOOTSTRAP_API_KEY` | `sk_` followed by the output of `openssl rand -hex 16` |
| `PHILTER_DEFAULT_POLICY` | Optional. Defaults to `comprehensive` |
</details>

Then install the mod. At the prompt of a Claude Code terminal session:

```
/plugin install philter-scrub --marketplace roberthallatt999/philter-guard
```

Answer `y` to add the marketplace, then pick the **user** scope. From a shell instead:

```bash
claude plugin install philter-scrub --marketplace roberthallatt999/philter-guard
```

In the desktop app, click **+** next to the prompt box, then **Plugins**, then **Add marketplace** with `roberthallatt999/philter-guard`, then **Add plugin**.

Run `/scrub` to check it's working.

## Using it

| | |
|---|---|
| `/scrub` | Show status and how many items were redacted this session |
| `/scrub off`, `/scrub on` | Turn scrubbing off (for example, to edit a file that holds real data) and back on |
| `/scrub images on`, `/scrub images off` | Let images and PDFs from tools through unredacted, or block them again |

**What's scrubbed:**
- What you type or paste
- Command output
- Search results
- Web pages
- Results from MCP connectors, such as database queries
- Any file read that isn't source code, such as `.log`, `.csv`, `.json` and SQL dumps

**What isn't scrubbed:**
- Source code reads
- Claude's own edit confirmations

**Screenshots:** Philter can't redact images. Pasting one opens a question: **Send it**, **Don't send** or **Allow for this session**. Images from tools are withheld until you run `/scrub images on`.

**If Philter is down:** your message isn't sent and tool output is withheld. Nothing gets through unredacted.

## Adding rules for a new project

1. Copy `projects/_example.json.disabled` to `projects/<project>.json`.
2. Add regex `identifiers` (with a `classification`) and word-list `dictionaries`. Remember that backslashes have to be doubled in JSON.
3. Run `./sync-policy.sh --dry-run` to check what will be uploaded, then `./sync-policy.sh` to upload it.

Commit the change so every computer gets it. On another computer, run `git pull && ./sync-policy.sh`.

## Limits

- Text already sent to Claude before the mod was on isn't covered.
- Some inputs never go through Philter: CLAUDE.md, memory files, slash-command arguments, and images you choose to send.
- Pattern-based detection over-redacts some ordinary numbers and misses unusual formats. Check placeholders in the output, and tune the policy when something slips through.
- The MCP server's `status` tool fails against Philter 4.0.1, because it calls `/api/status`. Use `curl -sk https://localhost:8080/api/health` instead.
