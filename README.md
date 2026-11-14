# philter-guard

Keeps personal and customer data out of Claude Code sessions. A local [Philter](https://github.com/philterd/philter) server redacts it first, so names, emails, phone numbers, SINs, health card numbers, addresses and similar details reach Claude as placeholders like `{{{REDACTED-email-address}}}`.

It's built for coding work where programs sometimes print customer data: logs, command output, database query results and data files are scrubbed. Source code is left alone so Claude can still edit it.

## What's in here

| Path | What it is |
|---|---|
| `docker-compose.yaml` | Philter 4 and the philter-mcp server, bound to localhost only |
| `policies/comprehensive.json` | The base redaction policy: built-in filters, Canadian and US identifiers, and ignore rules for paths, versions and log timestamps |
| `library/*.json` | Reusable pieces: regex patterns and word lists. `api-keys.json` is merged into every policy |
| `sets/*.json` | One file per client, listing which library pieces its policy includes |
| `sync-policy.sh` | Builds one policy per set, uploaded as `set-<name>` (plus `comprehensive`), from the base and library pieces, and uploads them. Philter uses them from the next request, with no restart |
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
| `/scrub` | Show status, the policy in use, and how many items were redacted this session |
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

## Choosing a policy per project

Put a file named `.philter` in the project folder. Its first line (blank lines and `#` comments are skipped) names a set from `sets/` (a file `sets/acme.json` is the set `acme`; on the server it is the policy `set-acme`):

```
# philter-guard set
acme
```

The mod looks for `.philter` in the folder Claude Code started in, then in each parent folder, and stops after the repository root (the first folder that is a repo top). It reads the file once, when the session starts, so the policy follows the starting folder and a change needs a new session. The mod only ever sends `set-<name>`, never the bare name, so a project can pick only a policy that `sync-policy.sh` built, and every one of those includes the base and the credential rules. It can't select a built-in or hand-made policy. When a set is active the status line always shows it, for example `🛡 Philter: 3 redacted · set acme`. With no file, the base policy `comprehensive` is used. The base includes the credential rules.

If the file can't be read or names an invalid set, or the set isn't on the server (run `./sync-policy.sh`), the base is used and the status line says `⚠ .philter unreadable or invalid, using base` or `⚠ policy "acme" not found, using base`. Nothing is blocked. `/scrub` shows the policy in use.

## Adding rules for a new project

Every policy is the base, `library/api-keys.json`, and the pieces a set includes. Every client gets the base and the API-key rules. A set can't opt out of them. On the server each set is the policy `set-<name>`.

1. Get the client's data schema (field names, ID formats, example values).
2. Turn it into rules in a piece: copy `library/_example.json.disabled` to `library/<piece>.json`. Add regex `identifiers` (with a `classification`) and word-list `dictionaries`. Remember that backslashes have to be doubled in JSON.
3. Add tests for the new patterns in `tests/cases/<piece>.py` (hyphens in the piece name become underscores), exporting `CASES = [(classification, text, must_catch_or_None), ...]`. Build every fake value at runtime from parts so no file holds a credential-shaped literal. `python3 tests/test_patterns.py` runs them for every piece.
4. Create the set: copy `sets/_example.json.disabled` to `sets/<client>.json` and list the piece names in `include`. Set names use lowercase letters, digits and hyphens. `comprehensive` is reserved.
5. Run `./sync-policy.sh --dry-run` to validate and see the summary, then `./sync-policy.sh` to upload. Anything on the server that is not `comprehensive` or a current `set-<name>` (including old un-prefixed set policies) is reported as `Stale (not deleted)`.

Run `bash tests/test_build.sh` to test the build itself. Commit the change so every computer gets it. On another computer, run `git pull && ./sync-policy.sh`.

## Limits

- The `.philter` set follows the folder the session started in. Changing directory inside a session doesn't change it.
- The secrets rules in `library/api-keys.json` are a backstop for the optimizer's access guard, not a replacement for it. They catch known key formats and labelled values only. There is no generic high-entropy rule, so unlabelled random strings pass through.
- Text already sent to Claude before the mod was on isn't covered.
- Some inputs never go through Philter: CLAUDE.md, memory files, slash-command arguments, and images you choose to send.
- Pattern-based detection over-redacts some ordinary numbers and misses unusual formats. Check placeholders in the output, and tune the policy when something slips through.
- The MCP server's `status` tool fails against Philter 4.0.1, because it calls `/api/status`. Use `curl -sk https://localhost:8080/api/health` instead.
