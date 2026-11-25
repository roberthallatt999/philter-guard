# Low-false-positive detection for Philter (proposal, 2026-11-23)

Status: applied 2026-11-24 (policies/, library/, sync-policy.sh, the philter-scrub plugin 0.3.0).
Changes made while applying: a filter's own `ignored` is a plain list of terms (`Set<String>` in
Phileas 4.5), not `{name, terms}` groups; the `ls -l` owner pattern is bounded
(`\S{1,64}[ \t]{1,16}`) because Philter refused `\S+[ \t]+` for exceeding its 1000 ms regex
budget; the code overlay gained `addIdentifiers` (labelled RAMQ and bank transit/account numbers),
since dropping their bare shapes left no rule for them in tool output; and the plugin rewrites
redacted Bash results only (Read, Grep, web and MCP results are still withheld as before).
`python3 tests/test_low_fp.py` now checks the live files; `--proposed` checks this proposal's file.
Rules: `docs/proposals/low-fp/proposed.py` (writes `proposed.json`). Corpus:
`tests/cases/low_fp_corpus.py`. Runner: `python3 tests/test_low_fp.py` (proposed: 101/101;
`--current`: 53/101).

## 1. What caused each false positive

Each one was reproduced with `explain_redactions` against the live `comprehensive` policy.

| Seen | Filter and confidence | Cause in Philter's code or config |
|---|---|---|
| `Digest::SHA`, `IO::Socket::INET`, `File::Path`, `POSIX::setsid`, `a::b::c`, `::error::`, `[::1]` | built-in `ipAddress`, 0.90 | Phileas's IPv6 pattern (`Ipv6Patterns.ADDRESS`) accepts the compressed form `::` with 0–4 hex digits on each side, so it matches `::`, `e::`, `::add`, `d::` and `a::b`. Nothing in the policy ignores these spans. |
| UUID path segment `4-5651-43` | built-in `phoneNumber`, **0.60** | libphonenumber's `POSSIBLE` leniency. `PhoneNumberRulesFilter` gives 0.95 only when the text is formatted like a phone number and 0.60 otherwise, and the policy redacts at any confidence. The same cause hits `192.168.0.0/16`, `169.254.0.0/16`, git's `00 2026 -0500` and `"0123456789abcdef"`. |
| UUID tail `446655440000` | built-in `trackingNumber`, 0.75 | Twelve digits look like a carrier tracking number. |
| `/Users/robert`, `robert  staff` (ls -l), `for n in` | `person` (ph-eye), 0.82–0.88 | The NER model runs on code output at threshold 0.8. The `file-paths` ignore pattern never helps here: Phileas tests `ignoredPatterns` with `Matcher.matches()` against **the span only** (`IgnoredPattern.matches`), and the span is `robert`, not the path. The model is inconsistent too: in one `ls -la`, the first row was redacted and the next five were not. |
| `Husky`, `Astro site`, `Philter`, `Squid` | `person`, about 0.85 | Same threshold. `ignored` terms are compared to the **whole span**, lower-cased and with whitespace collapsed (`Filter.isIgnored`), so the term `Astro` cannot stop the span `Astro site`. |
| `10.0.0.0/8`, `172.16.0.0/12` passed, `192.168.0.0/16` redacted | phone 0.60, not ip | Two problems. The phone filter catches the longer CIDRs. The IPv4 filter's spans are all thrown away, because the `version-numbers` ignore pattern fully matches any dotted quad. So **no IPv4 address is ever redacted today**, public ones included (`203.0.113.7` and `8.8.8.8` pass). |
| `GH_TOKEN: ai-egress-placeholder` | `secret-labelled-value` (colon rule) | The function-call exclusion `(?![A-Za-z_][A-Za-z_.]*(?:[(\[,;)\]]\|\s\|$))` stops at the `-`, so a hyphenated word goes through as a value. No digit or placeholder check is made. |
| `- ${EGRESS_DIR}/cloudflare/api-token:/home/...:ro`, `.../site.token:/run/relay.token:ro` | `secret-labelled-value` (colon rule) | The `token:` in a docker mount is read as a YAML key, and the path after it as the value. The value class allows a leading `/`. |
| `${PHILTER_BOOTSTRAP_API_KEY:?missing in .env}` leaving `${...:{{{REDACTED-…}}}` (the `${{`-looking text) | `secret-labelled-value` | `KEY:` followed by `?missing` reads as a value. The `${{{` you see is the placeholder written after `${...:`. A GitHub `${{ … }}` on its own is **not** redacted: that one couldn't be reproduced. |
| `"Bearer ${PHILTER_BOOTSTRAP_API_KEY}"` → `Bearer` redacted | quoted `secret-labelled-value` | The quoted rule takes the value up to the first `$` and doesn't need the closing quote. |
| `4111 1111 1111 1112` | `creditCard` | `onlyValidCreditCardNumbers: false`, so no Luhn check. |
| "a plugin withheld its result" | plugin | `register.ts` returns `{ deny: "[Philter redacted N items]\n…" }` whenever `count > 0`. Claude Code shows any `deny` as `<tool> ran, and a plugin withheld its result: …`, and the model reads it as an error. A single false positive turns a good result into an "error". |
| `DB_PASSWORD=your-password-here` (found while testing) | `secret-npm-auth` | `(?:_authToken\|_auth\|_password)\s*=` has no left boundary, so it matches the `_PASSWORD=` inside `DB_PASSWORD=`. |
| test files read with `cat` (`"0123456789abcdef"` and others) | phone 0.60 | The plugin skips scrubbing only for `Read` of a code file. `cat`/`sed` of the same file goes through Bash and is scrubbed. |

## 2. Proposed detection policy

Two policies per set: **prose** (what you type, unchanged name: `comprehensive` / `set-<name>`) and
**code** (tool output: `code-comprehensive` / `code-set-<name>`). Both share the secret library.

### Secrets (both policies). Low FP because each has a fixed prefix, length or structure

Keep the vendor-prefixed rules already in `library/api-keys.json`: AKIA/ASIA, `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`,
`github_pat_`, `sk-ant-`, OpenAI `sk-proj-` and similar, `xox[baprs]-`, `sk_live_`/`rk_live_`, `SG.x.y`, `AIza`, `glpat-` and similar, `npm_`,
`pypi-AgEIcHlwaS5vcmc`, PEM `-----BEGIN … PRIVATE KEY-----`, URL passwords, and the auth header. They match gitleaks'
default rules and GitHub's token formats, and none of them caused a false positive in this review.

Changes:

| Rule | Change | Why it's low FP |
|---|---|---|
| `secret-labelled-value` (4 rules) | The value must not start with `/ ~ ./ ../ ? : - $ % { < @ * \`, must not contain a placeholder word (`placeholder\|example\|changeme\|dummy\|redacted\|your-\|xxxx\|<word>`), and must contain a digit or one of `! # % ^ * + ~`. `KEY=` also accepts 12+ letters with a case change inside (`aBcD…`). YAML `key:` does not, matching the existing "no letters-only YAML" rule. A quoted value must reach its closing quote or the end of the line, so `"Bearer ${X}"` fails. A quoted phrase is accepted only with a digit or symbol, a 12+ run without spaces, or a case change. PHP `$cfg['password'] => '…'` is now covered. | This is gitleaks' generic-api-key idea (keyword plus a value that isn't a word: they use entropy 3.5 and the allowlist `^[a-zA-Z_.-]+$`) and the ai-config scanner's "a value needs a digit". It drops paths, shell expansions, templates and placeholders, the four seen today. Of the 137 existing `api_keys.py` cases, 136 still pass (below). |
| `secret-jwt` | Require `eyJ…\.eyJ…\.sig` (header **and** payload are JSON objects), with each part at least 10 characters | Same as gitleaks. A real JWT always has both. The one existing case that fails, #16, is synthetic: its payload doesn't start with `eyJ`. Change that case. |
| `secret-npm-auth` | `(?<![A-Za-z0-9])` before `_auth…`, plus the placeholder check | Matches only npmrc keys, not `DB_PASSWORD=`. |

There is still no generic entropy rule. Detect-secrets' high-entropy plugins are known for false positives on
hashes, UUIDs and lockfile integrity strings, so the existing reason for leaving one out still holds.

### Personal data

| Filter | Prose policy | Code policy | Why it's low FP |
|---|---|---|---|
| `phoneNumber` | `region: ["CA","US"]`, condition `confidence > 0.9` | same | Keeps only phone-formatted numbers (0.95). All six false positives seen were 0.60. Presidio's approach is the same: libphonenumber plus format/context. |
| `phone-number-dotted` (custom) | keep | keep | It is already anchored. |
| `person` | threshold **0.9**. `ignored`: tool words. `ignoredPatterns`: a single lower-case token, `ls -l` owner+group, and tool word + noun (`Astro site`, `the Husky hook`) | threshold **0.92**, same ignores | The false positives seen scored 0.825–0.879. Real names scored 0.962–0.993. A lower-case single token is a username or identifier in tool output. Note that `Jane Q. Public` was missed even at 0.8. |
| `ipAddress` | `ignoredPatterns`: scope-operator shapes (`[0-9a-f]{0,4}(::[0-9a-f]{0,4})+`), RFC 1918, loopback, link-local, CGNAT, doc ranges, fe80/fc00/2001:db8 | same | Only public addresses are left. Full-match semantics mean `2001:db8::1`-style real addresses with single colons aren't excused by the `::` rule. |
| `version-numbers` ignore | add `(?!(?:\d{1,3}\.){3}\d{1,3}\b)` | same | Stops it from ignoring every IPv4 address. Versions with a 4+ digit part (`10.0.19041.1`) are still ignored. **This adds redactions:** public IPs in `dig`/`ssh` output will start to be redacted. Leave this one out if that costs more than it protects. |
| `creditCard` | `onlyValidCreditCardNumbers: true` | same | Luhn. |
| `ssn`, `canadaSin`, `emailAddress`, `iban`, health-card **with label**, passport **with label**, MRN, DL **with label** | keep | keep | Already structural or labelled. |
| `trackingNumber`, `driversLicense` (built-in, >0.6), `vin`, `age`, `hospital` | keep | **disable** | They are shape-only. In command output they hit hashes, UUIDs and build ids. |
| bare passport `[A-Z]{2}\d{6}`, `[A-Z]\d{8}`; bare health card; bare RAMQ; bare DL; bare bank-account | keep | **drop** | They match build ids and epoch-style numbers. The existing suite already fails one: `test_patterns.py` reports 167/168 today because the bare health-card rule hits an epoch in a log line. |

## 3. File-by-file changes (not applied)

1. **`policies/comprehensive.json`**
   - `ignoredPatterns[version-numbers].pattern` → `VERSION_NUMBERS` in `proposed.json`.
   - `identifiers.person`, `.phoneNumber`, `.ipAddress`, `.creditCard` → `BUILTIN_OVERRIDES`. Per-filter `ignored` and
     `ignoredPatterns` are fields of Phileas `AbstractFilter`. After syncing, check with `explain_redactions` that ph-eye
     honours them on `person`; if not, put the person patterns at policy level.
2. **`library/api-keys.json`**: replace the four `secret-labelled-value` rules, `secret-jwt` and `secret-npm-auth` with
   the ones in `proposed.json`. Update `_about`: there are new value rules, and the known gaps are now letters-only YAML
   values and letters-only `KEY=` values without a case change.
3. **`policies/code-overlay.json`** (new): `CODE_OVERLAY`, which lists the built-ins to disable, the bare patterns to drop
   and the person threshold.
4. **`sync-policy.sh`**: for every built policy `X`, also build `code-X` (jq: delete the `disableBuiltins` keys from
   `.identifiers`, filter `.identifiers.identifiers` by `.pattern` not in `dropIdentifierPatterns`, and set
   `.identifiers.person.phEyeConfiguration.threshold`), then upload it the same way. Add `code-*` to the stale-policy check.
5. **`plugins/philter-scrub/hooks/register.ts`**
   - Keep a second name, `codePolicy` (`code-` + `policy ?? 'comprehensive'`), and check it in `resolvePolicy` with
     the `listPolicies` result you already have. Fall back to `policy` if it isn't on the server. `tool.call` uses
     `codePolicy`, and `prompt.submit` keeps `policy`.
   - Stop withholding results that were only redacted. For `Bash`, return
     `{ result: { ...ran.result, stdout: scrub(stdout), stderr: scrub(stderr) } }` with
     `[Philter redacted N items]` appended to stdout. For `Grep`/`Glob`/`Read` (data files), rewrite their text field
     the same way. Keep `deny` for cases that can't be rewritten (unknown result shape, Philter unreachable, images).
     Per the types, core checks a hook's `result` against the tool's output schema, so the model gets a normal result
     with placeholders instead of "a plugin withheld its result".
   - Tests in `tests/scrub.test.ts`: expect `res.result.stdout` instead of `res.deny`. Add cases: a redacted Bash
     result is not a deny; tool output uses the `code-` policy.
6. **`tests/cases/api_keys.py`**: change case 16 to a real JWT shape (payload starting with `eyJ`). Add the corpus's
   must-not-match lines.
7. **`tests/test_patterns.py`**: once the overlay exists, either move the epoch must-not-match into a code-policy test or
   tighten the bare health-card rule. It fails today.

## 4. Checking after a sync

```bash
python3 tests/test_patterns.py && python3 tests/test_low_fp.py && ./sync-policy.sh --dry-run
```
Then run `explain_redactions` (policy `code-comprehensive`) on the `SECRET_FP` lines and the Perl, ls and CIDR lines
in the corpus, and check that the count is 0. Run it on the `SECRET_TP` shapes and check that each is caught.

The regexes were checked with Python's `re` only: there's no JDK on this Mac, and the Java cross-check
(`Check.java` and its vectors) is in the session scratchpad. All constructs used (bounded lookbehind, `(?-i:…)`,
inline `(?i)`) are standard in `java.util.regex`.
