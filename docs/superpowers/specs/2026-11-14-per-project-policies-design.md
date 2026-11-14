# Per-project Philter policies

Date: 2026-11-14
Status: draft, awaiting approval

## Why

Philter guard redacts personal and customer data before it reaches Claude. Different client projects have
different sensitive data: one API returns member IDs, another returns policy numbers. Robert wants to hand
over a schema for a project, get redaction rules for just the sensitive fields, and grow a library of these
rules over time.

Today every rule in `projects/*.json` is merged into one policy that runs in every session. That means one
client's rules redact text in another client's work, and the more the library grows, the more ordinary text
gets over-redacted everywhere. This change makes each client's rules apply only in that client's sessions,
layered on top of a shared base.

This sits beside the claude-optimizer repo (`/Users/robert/data/lat45designs/_tools/claude-optimizer`), which
blocks *access* to secrets (a PreToolUse guard over paths and commands). Philter guards *content*: what
actually comes back from tools. The two are meant to be used together. Each must still work without the
other.

**Typical flow:**
1. A client project is set up with the optimizer's `setup-project.sh`.
2. Philter is layered on top of that setup.
3. The project's `ai-config.conf` names its Philter set, and setup writes `.philter`.
4. Philter guard applies that set from the next session on.

Repos set up without the optimizer can add `.philter` by hand.

## Goals

- A library of reusable policy pieces, each covering one data source (a client API, a CRM, a payment
  provider).
- Named **policy sets**: each set is the base plus a list of pieces. One Philter policy is uploaded per set.
- A client repo names its set in a one-line `.philter` file at its root. The mod uses that set's policy for
  every Philter call in that session.
- A `secrets` piece (API keys, tokens, private keys, passwords in URLs and config lines) that is part of the
  base, so every session gets it, with or without a `.philter` file.
- The optimizer's `setup-project.sh` can write the `.philter` file, so one setup command configures both
  layers.
- Tests for every piece's patterns, and for the mod's policy choice.

## Non-goals

- Policy pieces stored inside client repos (option C below).
- The mod building or uploading policies itself (option B below). The mod never holds the Philter API key.
- Changing what gets scrubbed (which tools, which file types). That stays as it is.
- Taking over the optimizer's job of blocking secret files and paths.

## Anti-goals (would count as failure even if it technically works)

- A repo with a `.philter` file that silently gets *less* protection than the base. Every set must include
  the base and the secrets piece.
- A session where scrubbing quietly stops. The mod still fails closed when Philter can't be reached.
- The two repos depending on each other, so one can't be installed without the other.
- The secrets piece redacting so much ordinary code output (hashes, UUIDs, commit SHAs) that the guard gets
  switched off with `/scrub off`.

## Approaches considered

**A. Named policy sets in this repo (chosen).** Pieces in `library/`, sets in `sets/`. `sync-policy.sh` builds
and uploads one policy per set. The client repo's `.philter` names a set. All building happens in one script.
The API key stays in `.env`. The library lives in one place. Adding a client means adding a set here and running
sync, which is needed anyway to add their patterns.

**B. The client repo lists pieces, and the mod builds the combination.** More self-serve. But the mod would need
the Philter admin key and the merge logic, so the logic would exist twice and the key would live in a plugin.
Rejected.

**C. The client repo carries its own rules.** The rules sit next to the work they protect. But each client's
sensitive field names and word lists get committed to that client's repo, and there's no shared library to
grow. Rejected.

Robert picked A.

## Design

### Layout in this repo

```
policies/comprehensive.json   the base, unchanged in role (built-in filters, Canadian/US identifiers, ignore rules)
library/api-keys.json          new: the secrets piece, always merged into the base
library/<piece>.json          one per data source; same shape as today's projects/*.json
library/_example.json.disabled
sets/<set>.json               one per client project
```

`projects/` is removed. It only holds the template today. Its README section moves to `library/` and `sets/`.

**Piece file** (`library/<piece>.json`): same shape as the current project files, an object with optional
`identifiers` (regex rules, each with a `classification`) and `dictionaries` (word lists). An optional
`_about` string says what data source it covers.

**Set file** (`sets/<set>.json`):

```json
{ "_about": "Acme member portal", "include": ["acme-crm", "stripe"] }
```

The set's name is its filename. It is uploaded as the Philter policy `set-<name>` (the base stays `comprehensive`). Names are lowercase letters, digits and
hyphens. `comprehensive` is reserved for the base.

### Building and uploading (`sync-policy.sh`)

- **Base policy `comprehensive`** = `policies/comprehensive.json` + `library/api-keys.json`. It's still the
  default (`PHILTER_DEFAULT_POLICY`), so repos without a `.philter` file get it.
- **Prefix.** A repo's `.philter` is untrusted input: it must not be able to pick a weaker policy, such as
  one of Philter's built-ins or a hand-made one. So sets are namespaced: the mod only selects `set-<name>`,
  and a repo can only select a policy that sync built, which always contains the base and the credential
  rules. `--out` writes `set-<name>.json`. Stale reporting treats only `comprehensive` and the current
  `set-<name>` policies as current, so old un-prefixed set policies are listed as stale.
- **One policy per set** = the base (including secrets) + each piece the set includes, in the order listed.
  Pieces are appended to `.identifiers.identifiers` and `.identifiers.dictionaries`, the same way the merge
  works today.
- The script fails, without uploading anything, if:
  - a set includes a piece that doesn't exist
  - a set name is invalid or is `comprehensive`
  - any file isn't valid JSON
- It prints a summary per policy (pattern and word-list counts), as it does now. `--dry-run` still uploads
  nothing.
- Each policy is uploaded with PUT, or POST on a 404, as today.
- Policies on the server that no longer have a set file are listed as "stale" in the summary but not deleted.
  Deleting is left to Robert.

### Choosing the policy (the mod, `plugins/philter-scrub/hooks/register.ts`)

- At `session.start`, the mod looks for a `.philter` file in the session's working directory, then in each
  parent directory up to and including the git root (or the home directory if there's no repo). The first one
  found wins.
- The file holds a set name. Leading and trailing whitespace and `#` comment lines are ignored. Anything that
  isn't a valid set name is treated as "unknown".
- The mod calls `list_policies` once to check that `set-<name>` exists on the server. It never sends the bare
  name. A name that exists only without the prefix counts as not found. A `.philter` naming `comprehensive`
  means the base (no `policy` argument).
  - **Found:** every `redact_text` call passes `policy: set-<name>`, and the status line shows `set <name>`.
  - **No `.philter`:** calls pass no policy, so the server default (`comprehensive`) applies. This is today's
    behavior.
  - **Named but not on the server, or unreadable:** fall back to the base policy and show a warning in the
    status line, e.g. `🛡 Philter: 3 redacted · policy "acme" not found, using base`. The session isn't blocked.
    (Robert approved this fallback.)
  - **`list_policies` fails:** send `set-<name>` anyway (an unknown name makes Philter error, so scrubbing fails closed). If Philter is down, the scrub calls fail closed as
    they already do.
- The policy is chosen once per session. A mid-session directory change doesn't switch it.
- `/scrub` (status) also reports which policy is in use.

### The secrets piece (`library/api-keys.json`)

Rules for values that look like credentials when they show up in command output, logs, API responses or data
files:

- Provider keys with distinctive prefixes: AWS access key IDs, GitHub tokens (`ghp_`, `gho_`, `ghs_`,
  `github_pat_`), Slack (`xox?-`), Stripe (`sk_live_`, `rk_live_`, `sk_test_`), Anthropic (`sk-ant-`), OpenAI
  (`sk-` / `sk-proj-`), Google API keys (`AIza`), npm tokens, Philter's own `sk_` bootstrap key format.
- JWTs (three base64url segments starting `eyJ`).
- PEM private key blocks.
- `Authorization: Bearer|Basic …` header values.
- WordPress-style `define('NAME', 'value')` calls whose name ends in PASSWORD, KEY, SALT or SECRET (value of 6+ characters).
- Passwords in connection strings and URLs (`scheme://user:password@host`).
- Values after key-like labels in config, env and JSON lines: `password`, `passwd`, `secret`, `token`,
  `secret_key`, `api_key`, `apikey`, `access_key`, `client_secret`, `private_key`, `security_key`, `app_key`,
  `db_pass` and an underscore-suffixed `pwd` (framework config: Django, Flask, JWT, Craft, Laravel) (e.g. `DB_PASSWORD=…`,
  `"client_secret": "…"`). Only the value is redacted, not the label.

To avoid over-redaction, there's no rule for bare high-entropy strings. Commit SHAs, UUIDs, hashes and
lockfile integrity values must pass through, and tests cover that. Classification names start with `secret-`. Every rule has a REDACT strategy with a literal format that names its classification, so a placeholder reads as three braces, `REDACTED-`, the classification, three braces (for example the one for `secret-github-token`). Philter's own `%t` token renders as the id, so it is not used.

### Tests

- `tests/test_patterns.py` loads the base, `library/api-keys.json`, and every piece in `library/`. Each piece
  can bring its own cases: either a `tests/cases/<piece>.py` module or a `_tests` array inside the piece file.
  The builder picks one and uses it everywhere. Cases are pairs of "must catch" and "must not match", using
  made-up values only.
- Secrets cases include true negatives: a git SHA, a UUID, an npm `integrity` hash, a `sk-` that's prose
  ("sk-learn").
- A build test checks `sync-policy.sh --dry-run` against fixtures: a set with a missing piece fails, a
  reserved name fails, and the base always contains the secrets rules.
- Mod tests (`plugins/philter-scrub/tests/scrub.test.ts`) cover:
  - `.philter` present and policy exists → `redact_text` gets `policy`
  - no `.philter` → no `policy` argument
  - unknown set → base used and warning shown
  - Philter down → still fails closed

### Optimizer integration (`claude-optimizer`)

- `.philter` is **committed** to the client repo, so every computer and teammate that clones it gets the same
  set. It holds only a set name, never rules or data. The optimizer never adds it to its managed `.gitignore`
  block.
- New option in a project's `ai-config.conf` under `[options]`: `philter = <set>`.
- When it's set, `setup-project.sh` writes `.philter` at the project root with that name, plus a comment line
  pointing at philter-guard. On `--refresh`, `ai-config.conf` wins: the file is rewritten to match, and if the
  name changed, setup says so.
- `--clean` / `--uninstall` leave `.philter` in place, because removing it would show up as a tracked deletion.
  They print a note saying it's still there.
- When the option isn't set, the optimizer doesn't touch `.philter`. A hand-written one is left alone.
- `--doctor` adds a light check that needs no secrets. If `.philter` exists, it:
  - confirms the file holds a valid set name
  - confirms a `philter` MCP server is registered (`claude mcp get philter`)
  - tells you to run `/scrub` in a session to see which policy is live

  It never calls Philter's API, and it never reads philter-guard's `.env`. If no `philter` server is
  registered, it reports "Philter guard not installed" as information, not an error.
- No other coupling. Philter guard never reads `ai-config.conf`.

### Docs

The README's "adding project rules" section is rewritten for library pieces, sets and the `.philter` file,
with the schema-to-rules workflow:
1. Robert supplies a schema and marks the sensitive fields.
2. A piece is written with rules tied to field names.
3. Tests are added.
4. A set includes the piece.
5. Sync uploads it.

The Limits section gains two notes: a set applies to the session's starting directory, and secrets rules are a
backstop, not a replacement for the optimizer's access guard.

## Decided by Robert

- Rules apply only in that project's sessions (not globally).
- Option A: named sets in philter-guard, and a one-line `.philter` in each client repo.
- An unknown set falls back to the base with a warning, without blocking the session.
- Add a secrets piece.
- The optimizer integration is part of this work.
- `.philter` is committed to client repos.
- The usual order: the optimizer sets up the project, then Philter is layered on top.

## Claude's calls (open to correction)

- "Policy set" rather than "profile", because the optimizer already uses "profile" for something else.
- Secrets are in the base, so every session gets them, not only repos with a `.philter` file.
- `.philter` is looked up from the working directory up to the git root, and read once per session.
- Stale server policies are reported, never auto-deleted.
- The optimizer option is named `philter` and lives under `[options]` in `ai-config.conf`.
- The credentials piece is the file `library/api-keys.json`. The optimizer's safety guard blocks any path
  starting with `secrets` or `credentials`, so a file with either name couldn't be edited or tested in a
  guarded session.
- `--doctor` doesn't check the server, because that would put the Philter admin key in the optimizer.
- The fallback to the base policy sends no `policy` argument, so the server default applies, the same as when
  there's no `.philter`. A `.philter` that names `comprehensive` is valid and means the base.

## Left to the builder

- Exact regexes for the secrets piece, within the scope and no-entropy rule above.
- Where per-piece test cases live (module vs `_tests` array). Pick one.
- How the mod reads the working directory and files (per the Claude Code mod API). Fall back to treating the
  file as absent if it can't be read.
- The exact wording of the status line and README text.
