# Per-project Philter Policies Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let each client repo pick a named Philter policy set (base + secrets + that client's pieces) through a committed `.philter` file, with the claude-optimizer able to write that file.

**Architecture:** `sync-policy.sh` builds one Philter policy per `sets/<set>.json` from `policies/comprehensive.json` + `library/api-keys.json` + the set's listed `library/*.json` pieces, and uploads each. The philter-scrub mod finds `.philter` at session start, checks the set exists with `list_policies`, and passes `policy` on every `redact_text` call. The optimizer's `setup-project.sh` writes `.philter` from `philter = <set>` in `ai-config.conf`.

**Tech Stack:** bash + jq (sync), Python 3 (pattern tests), TypeScript Claude Code mod (`claude plugin test`), bash (optimizer, `test-*.sh` suites).

**Spec:** `docs/superpowers/specs/2026-11-14-per-project-policies-design.md`

## Global Constraints

- Set names: lowercase letters, digits, hyphens (`^[a-z0-9][a-z0-9-]*$`). `comprehensive` is reserved for the base, and is also a valid `.philter` value meaning "base".
- Every built policy contains the base and `library/api-keys.json`. No set can opt out.
- The mod never holds the Philter API key. It only calls the `philter` MCP server (`redact_text`, `list_policies`).
- The mod still fails closed when Philter can't be reached. That behaviour and its existing tests are unchanged.
- Fallback to the base (`.philter` names a set that isn't on the server, or the file can't be read) sends **no** `policy` argument and shows a warning in the status line. It never blocks.
- The policy is chosen once per session, at `session.start`.
- `.philter` is committed in client repos. The optimizer never gitignores it and never deletes it.
- The optimizer never calls Philter's API and never reads philter-guard's `.env`.
- Neither repo requires the other to be installed.
- Secret classifications start with `secret-`. There's no generic high-entropy rule. Git SHAs, UUIDs, lockfile `integrity` hashes and prose like "sk-learn" must pass through.
- Test values are made up, never real data.

## Review Focus

1. **`.philter` written on Windows or by an editor** (CRLF line endings, UTF-8 BOM, trailing blank lines, a `#` comment line): the set name is still read correctly. Test in Task 3.
2. **Session started in a subfolder of a client repo**: the `.philter` at the repo root is found, and a `.philter` above the git root (e.g. in `~`) is not. Test in Task 3.
3. **Philter down at session start** (`list_policies` throws): the named set is still used, with no "not found" warning, and scrub calls still fail closed. Test in Task 3.
4. **A set that lists the same piece twice, or two sets sharing a piece**: each piece is merged once per policy. Building one set doesn't leak into another. Test in Task 1.
5. **Prose next to secret labels** ("password reset email sent", "token: <none>", `api_key=` with an empty value): no redaction. A real value after the label is redacted with the label kept. Test in Task 2.

---

## Before starting

`policies/comprehensive.json` has an uncommitted change and `tests/test_patterns.py` is untracked. Both are Robert's own work. Ask Robert to commit them, or get his OK to commit them as-is, before Task 1. Task 2 edits `tests/test_patterns.py`.

Work on `main` in philter-mcp, as its history does. In claude-optimizer, check the current branch before Task 4 and ask if it isn't the usual one.

---

### Task 1: Library, sets and the multi-policy build

**Files:**
- Create: `library/_example.json.disabled` (moved from `projects/_example.json.disabled`; same content, `_about` text updated)
- Create: `library/api-keys.json` (placeholder `{ "_about": "Credentials. Always merged into every policy.", "identifiers": [] }`. Task 2 fills it.)
- Create: `sets/_example.json.disabled` → `{ "_about": "Template. Copy to sets/<client>.json.", "include": ["example"] }`
- Delete: `projects/` (only the template lives there)
- Modify: `sync-policy.sh`
- Create: `tests/test_build.sh`, `tests/fixtures/build/` (a tiny base, `library/api-keys.json`, `library/a.json`, `library/b.json`, sets)
- Modify: `README.md` (the "adding project rules" section and the What's-in-here table)

**Interfaces:**
- Produces: `sync-policy.sh [--dry-run] [--root DIR] [--out DIR]`
  - `--root DIR`: read `policies/`, `library/` and `sets/` under DIR (default: the script's folder).
  - `--out DIR`: write each built policy to `DIR/<name>.json` and upload nothing.
  - Exit 0 on success. Exit 1 on any validation error, with nothing written or uploaded.
- Produces: policy names `comprehensive` plus one per `sets/<name>.json`.

- [ ] **Step 1: Write `tests/test_build.sh`** (bash, same pass/fail counter style as claude-optimizer's suites, exit 1 on any failure). It runs `sync-policy.sh --root tests/fixtures/build --out $tmp` and asserts:
  - `comprehensive.json` and `acme.json` are written. Nothing is written for `_example.json.disabled`.
  - `comprehensive` contains the `secret-fixture` classification from the fixture secrets.
  - `acme` (`include: ["a","a","b"]`) contains the classifications from a and b **exactly once each**, plus `secret-fixture`, plus the base's.
  - `other` (`include: ["b"]`) contains nothing from a.
  - A fixture copy where a set includes `"missing"` exits 1, the message names `missing`, and `--out` stays empty.
  - A set file named `sets/comprehensive.json` exits 1. So does `sets/Bad_Name.json`, and a piece with invalid JSON.
  - `--dry-run --root … ` prints one summary line per policy and never needs `.env`.
- [ ] **Step 2: Run it and check it fails.** Run: `bash tests/test_build.sh`. Expected: FAIL (unknown `--root`).
- [ ] **Step 3: Rewrite `sync-policy.sh`.**
  - Validate everything first, then build all policies into a temp dir, then upload or copy to `--out`.
  - Use the existing jq merge, appending to `.identifiers.identifiers` and `.identifiers.dictionaries`. Dedupe the set's include list while keeping order.
  - Drop every top-level key starting with `_` (`_about`, `_tests`) from pieces before merging. Add a test assertion that no built policy contains `_tests`.
  - In upload mode, after the uploads, `GET /api/policies` and print any name that isn't `comprehensive` or a current set as `Stale (not deleted): …`.
  - If one upload fails, keep going, then print which policies uploaded and which failed, and exit 1.
- [ ] **Step 4: Run the tests and check they pass.** Run: `bash tests/test_build.sh && ./sync-policy.sh --dry-run`. Expected: all PASS, and the dry run lists `comprehensive`.
- [ ] **Step 5: Update the README.**
  - Replace the `projects/*.json` row with `library/*.json` (pieces) and `sets/*.json` (one per client).
  - Rewrite "adding project rules" as the schema-to-rules workflow from the spec's Docs section: schema → piece → tests → set → sync.
- [ ] **Step 6: Commit.** `git add -A library sets projects sync-policy.sh tests/test_build.sh tests/fixtures README.md && git commit -m "Policy sets: build one Philter policy per sets/*.json"`

### Task 2: The secrets piece and per-piece pattern tests

**Files:**
- Modify: `library/api-keys.json`
- Modify: `tests/test_patterns.py`
- Modify: `README.md` (Limits: secrets rules are a backstop for the optimizer's access guard, not a replacement)

**Interfaces:**
- Consumes: the Task 1 layout. The base always merges `library/api-keys.json`.
- Produces: the per-piece test convention. `tests/cases/<piece>.py` exports `CASES = [(classification, text, must_catch_or_None), …]`, with the same meaning as the existing `CASES`. A file name's hyphens become underscores (`api-keys` → `api_keys.py`).

- [ ] **Step 1: Extend `tests/test_patterns.py`** so it loads patterns from the base plus every `library/*.json`, and runs the base `CASES` plus every `tests/cases/*.py` module's `CASES`. A failing line says which piece it came from, and prints classification and pass/fail only, never the value: printed fake credentials trip the guard and the redactor.
- [ ] **Step 2: Write `tests/cases/api_keys.py`** (a `CASES` list, same tuple shape), with no patterns in the piece yet.

  **Ruling (controller):** no file may contain a credential-shaped literal. The safety guard refuses to read such files, and GitHub secret scanning would flag them. Build every fake value at runtime from parts, e.g. `"AK" + "IA" + "A" * 16`, or a prefix joined to `"x" * n`.

  This replaces the `_tests` convention: every piece's cases live in `tests/cases/<piece>.py`, which `test_patterns.py` imports.

  Must catch, one case per classification, each value assembled at runtime:
  - `secret-aws-access-key`: an AWS access-key-ID-shaped value
  - `secret-github-token`: the classic and fine-grained GitHub token forms
  - `secret-slack-token`: a bot token form
  - `secret-stripe-key`: a live secret key form
  - `secret-anthropic-key`
  - `secret-openai-key` (project key form)
  - `secret-google-api-key`
  - `secret-npm-token`
  - `secret-philter-key`: the bootstrap form, a 3-character prefix + 32 hex
  - `secret-jwt`: three base64url segments
  - `secret-private-key`: a PEM private-key header and body
  - `secret-auth-header`: a bearer header. Only the value is caught.
  - `secret-url-password`: a database URL with user and password. Only the password is caught.
  - `secret-labelled-value`: an uppercase env line ending in PASSWORD, a JSON client-secret pair, and an access-token query parameter. Only the value is caught in each.

  Must not match (`None`), each checked against **every** `secret-` classification:
  - a 40-hex git SHA
  - a UUID
  - `"integrity": "sha512-…=="`
  - `scikit-learn (sk-learn)`
  - `password reset email sent`
  - `token: <none>`
  - `api_key=` at the end of a line
  - `Authorization: Bearer` with no value
- [ ] **Step 3: Run it and check it fails.** Run: `python3 tests/test_patterns.py`. Expected: the new secrets cases FAIL, and the base cases still pass.
- [ ] **Step 4: Write the `identifiers` in `library/api-keys.json`.** Use one entry per classification above, each with `identifierFilterStrategies: [{ "strategy": "REDACT", "redactionFormat": "{{{REDACTED-%t}}}" }]`. Use `groupNumber` where only the value is caught. Labels for `secret-labelled-value`: password, passwd, pwd, secret, token, api_key/apikey/api-key, access_key, client_secret, private_key, as a whole key or a key suffix (`DB_PASSWORD`). Values need 6 or more characters with no whitespace or quotes.

  The helper checks a "must not match" case only against its own classification. For the shared no-match list, add a loop that checks those texts against all `secret-*` patterns.
- [ ] **Step 5: Run the tests and check they pass.** Run: `python3 tests/test_patterns.py && bash tests/test_build.sh`. Expected: all pass.
- [ ] **Step 6: Check against the live server.**
  1. Run `./sync-policy.sh`.
  2. Call `mcp__philter__redact_text` with policy `comprehensive` on two lines: one with a fake GitHub token, and one with a git SHA and a UUID.
  3. Expected: the token comes back as `{{{REDACTED-secret-github-token}}}`, and the SHA and UUID come back unchanged.

  Java's regex engine is the final word. Fix any pattern that Python accepts but Philter rejects.
- [ ] **Step 7: Commit.** `git commit -am "Policy: secrets piece in every policy, per-piece pattern tests"` (add `library/api-keys.json`).

### Task 3: The mod picks the policy from `.philter`

**Files:**
- Modify: `plugins/philter-scrub/hooks/register.ts`
- Modify: `plugins/philter-scrub/tests/scrub.test.ts`
- Modify: `plugins/philter-scrub/.claude-plugin/plugin.json` (version `0.2.0`)
- Modify: `README.md` (a `.philter` section, and the `/scrub` row now reports the policy. Limits: the set follows the session's starting folder.)

**Interfaces:**
- Consumes: policy names from Task 1. The MCP tools `list_policies` (returns policy names in its text block) and `redact_text({ text, policy? })`.
- Produces, in `register.ts`:
  - `parseSetName(text: string): string | null`: strips a BOM, splits on `\r?\n`, ignores blank and `#` lines, and returns the first remaining line trimmed if it matches the set-name rule, else `null`.
  - `findPhilterFile($: EngineInterface, cwd: string): Promise<string | null>`: checks `<dir>/.philter` from `cwd` upward. It stops after the first dir that holds `.git` (file or folder) or equals the home dir, and at `/`.
  - Module state: `policy: string | undefined` (the name sent to Philter) and `policyNote: string` (empty, or the warning text).
  - `scrub()` passes `policy` only when it's defined.

  Read the API from `/private/tmp/claude-501/bundled-skills/2.1.325/3eae36b6ef1953a516817854f6fd727d/plugin-authoring/types/claude-code.d.ts`, or the mod's `.claude-plugin/types/` once loaded:
  - `SessionStartInput.cwd`
  - `$.fs.exists(path)` and `$.fs.read(path)` (rejects when missing)
  - the home directory, from whatever `$` exposes. If nothing does, stop at the git root or `/`.

- [ ] **Step 1: Write the failing tests** in `scrub.test.ts`. Each one stubs `fs.exists`, `fs.read` and `mcp.call` (branching on the tool name), and starts with `await $.session.start({ cwd, surface: 'terminal', isInteractive: true })`.
  - `uses the set named in .philter`: `/w/acme/.philter` = `"acme\n"`, `/w/acme/.git` exists, and `list_policies` returns `["comprehensive","acme"]`. Then a tool result is scrubbed, and the recorded `redact_text` args include `policy: 'acme'`.
  - `no .philter means no policy argument`: `redact_text` args have no `policy` key.
  - `finds .philter from a subfolder but not above the git root`: cwd `/w/acme/src/app` finds `/w/acme/.philter`. A second case has `.philter` only at `/w` and `.git` at `/w/acme`, so there's no policy argument.
  - `reads CRLF, BOM and comments`: the file is `"﻿# philter-guard set\r\nacme\r\n"`, so the policy is `acme`.
  - `unknown set falls back to base with a warning`: `list_policies` returns `["comprehensive"]`. There's no `policy` arg, and the last `ui.status` text contains `policy "acme" not found, using base`.
  - `invalid name falls back with a warning`: the file is `"Acme Corp"`. Same assertions, with a warning naming the file as unreadable or invalid.
  - `list_policies failing still uses the named set`: `list_policies` throws, so `policy: 'acme'` is sent and the status has no warning.
  - `/scrub reports the policy`: the output text contains `Policy: acme`, or `Policy: base (comprehensive)` when there's no file.
  - Keep the existing fail-closed tests passing unchanged.
- [ ] **Step 2: Run them and check they fail.** Run: `claude plugin test plugins/philter-scrub`. Expected: the new tests FAIL, and the existing ones PASS.
- [ ] **Step 3: Implement.**
  - In `session.start`, before `showCount`, resolve the policy: find the file, parse it, then run `list_policies` and set `policy`/`policyNote` per the Global Constraints. Wrap everything in try/catch: anything thrown before the parse counts as unreadable.
  - `showCount` appends ` · ${policyNote}` when it's set. `/scrub` adds the `Policy: …` line.
  - Because `session.start` runs again on a reload, reset `policy` and `policyNote` at its top.
- [ ] **Step 4: Run the tests and check they pass.** Run: `claude plugin test plugins/philter-scrub && claude plugin validate plugins/philter-scrub`. Expected: all pass, and validate reports nothing refused.
- [ ] **Step 5: Update the README** with what `.philter` is, an example, where it's looked for, and what the status line shows on a fallback.
- [ ] **Step 6: Commit.** `git commit -am "philter-scrub: use the policy set named in .philter"`

### Task 4: claude-optimizer writes `.philter` (in `/Users/robert/data/lat45designs/_tools/claude-optimizer`)

**Files:**
- Modify: `setup-project.sh`:
  - `apply_project_policy` case list near line 346, so it no longer warns about an unknown key
  - setup or refresh flow
  - `do_clean` (~4322)
  - `do_uninstall` (~3712)
  - doctor section (~5064)
- Create: `test-philter.sh` (same style as `test-project-policy.sh`)
- Modify: the docs page that lists `[options]` keys (find it with `grep -rn "okf-memory" docs`)

**Interfaces:**
- Consumes: the `.philter` format from Task 3: one set name, optionally preceded by `#` comment lines.
- Produces: `philter = <set>` under `[options]`. A file the optimizer writes is exactly:
  ```
  # Philter policy set, written by ai-config from ai-config.conf (philter = …). See philter-guard.
  <set>
  ```
  The first line is the marker that tells the optimizer it wrote the file.

- [ ] **Step 1: Write `test-philter.sh`** using temp projects and the existing `assert_*` helpers:
  - `philter = acme` + setup: `.philter` exists with the marker line and `acme`.
  - No `.gitignore` line matches `.philter` after setup.
  - `--refresh` after changing the conf to `philter = beta`: the file holds `beta`, and the output mentions the change from `acme` to `beta`.
  - No `philter` option and a hand-written `.philter` (no marker): setup and refresh leave it byte-identical.
  - An invalid value (`philter = Acme Corp`): setup warns and doesn't write the file.
  - `--clean` and `--uninstall`: `.philter` is still there and the output notes it.
  - `--doctor` with `.philter` = `acme` and `AI_CONFIG_FAKE_MCP_PHILTER=1` (or however the suite already fakes `claude mcp get`; reuse that): it reports the set name and the `/scrub` hint. Without the philter server, it reports "Philter guard not installed" and exits with the same code it would otherwise.
- [ ] **Step 2: Run it and check it fails.** Run: `./run-tests.sh philter`. Expected: FAIL.
- [ ] **Step 3: Implement** each behaviour the tests name. The doctor's MCP check uses the `claude mcp get` pattern the script already uses for codegraph.
- [ ] **Step 4: Run the tests and check they pass.** Run: `./run-tests.sh philter project-policy lifecycle`. Expected: all pass. The existing suites show nothing has regressed.
- [ ] **Step 5: Document** `philter` in the `[options]` docs: what it does, that `.philter` is committed, and that philter-guard is optional.
- [ ] **Step 6: Commit (in the optimizer repo).** `git add setup-project.sh test-philter.sh docs && git commit -m "ai-config: write .philter from philter = <set>"`

### Task 5: End-to-end check

- [ ] **Step 1: Set up a scratch set.**
  1. Create `library/demo.json` with one identifier: classification `demo-member-id`, pattern `\bMBR-\d{6}\b`.
  2. Create `sets/demo.json` with `include: ["demo"]`.
  3. Run `./sync-policy.sh`. Expected: `demo` uploaded.
- [ ] **Step 2: Confirm the set applies only where it's named.**
  1. Call `mcp__philter__redact_text` with `policy: "demo"` on `member MBR-123456`. Expected: `{{{REDACTED-demo-member-id}}}`.
  2. Repeat with `policy: "comprehensive"`. Expected: unchanged.
- [ ] **Step 3: Remove the scratch files.** Delete `library/demo.json` and `sets/demo.json`, then run sync again. Expected: `demo` is listed under "Stale (not deleted)".
- [ ] **Step 4: Report back.** Tell Robert the stale `demo` policy is still on the server, and give him the delete command (`curl -sk -X DELETE … /api/policies/demo` with his key) to run himself. Nothing to commit.
