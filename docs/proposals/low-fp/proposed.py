#!/usr/bin/env python3
"""Proposed low-false-positive rules for the Philter policies (2026-11-23).

Single source for the proposal: tests/test_low_fp.py imports it, and running this file
writes proposed.json next to it in the shape policies/ and library/ use, so the changes
can be pasted in. Nothing here is uploaded anywhere.

    python3 docs/proposals/low-fp/proposed.py     # writes docs/proposals/low-fp/proposed.json
"""
import json
import pathlib

FMT = "{{{REDACTED-%s}}}"

# ---------------------------------------------------------------------------
# 1. Shared label list, unchanged from library/api-keys.json.
# ---------------------------------------------------------------------------
LABEL = (
    r"(?:password|passwd|(?<=_)pwd(?![\"']?[ \t]*[:=][ \t]*[\"']?/)|secret|secret[_-]?key|token"
    r"|api[_-]?key|access[_-]?key|client[_-]secret|private[_-]key|security[_-]?key"
    r"|(?<![A-Za-z])app[_-]?key|(?:db|database)[_-]?pass)"
)

# Values that are never a literal secret: paths (/x ~/x ./x), shell expansion tails
# (${VAR:?msg}, ${VAR:-default}), variables/templates ($X {X} {{X}} %X% <X>), globs.
NOT_A_LITERAL_START = r"(?![/~?:\-$%{<@*\\]|\.{1,2}/)"

# Placeholder words: the value is documentation or a stand-in, not a credential.
PLACEHOLDER = r"(?:placeholder|example|changeme|change[_-]me|dummy|redacted|your[_-]|xxxx|<[a-z_-]+>)"

# Unquoted value: must hold a digit or a symbol a word or identifier never has, as the
# ai-config scanner already requires ("a value needs a digit"). Kills ai-egress-placeholder,
# validation rules (required|min:8 has a digit but '|' stops the value), labels, YAML words.
def unquoted_value(allow_letters):
  return (
    NOT_A_LITERAL_START
    + r"(?!(?:string|number|boolean|null|none|true|false|undefined|required|optional)\b)"
    + r"(?![A-Za-z_]\w*[(\[])"                                    # a function call or index
    + r"(?![A-Za-z_]+(?:\.[A-Za-z_]+)+(?:[;,)\](\[]|\s|$))"       # a dotted attribute
    + r"(?![^\s\"']*" + PLACEHOLDER + r")"
    + r"(?:(?=[^\s\"'&;,)\]]*[\d!#%^*+~])"                       # a digit or symbol, or
    + (r"|(?=[A-Za-z]{12})(?=[^\s\"'&;,)\]]*(?-i:[a-z][A-Z]))" if allow_letters else "")  # KEY=MixedCaseLetters
    + r")([^\s\"'<>{$(\[&;,)\]]{8,})"
  )

# Quoted value: the closing quote must follow (so "Bearer ${X}" is not cut at the $), and the
# value must hold a digit/symbol or be one 12+ character run without spaces (a phrase like
# "Enter your token" is a label, not a secret).
def quoted_value(q):
    return (
        q
        + NOT_A_LITERAL_START
        + r"(?!(?:string|number|boolean|null|none|true|false|undefined)" + q + r")"
        + r"(?![^" + q + r"\r\n]*" + PLACEHOLDER + r")"
        + r"(?:(?=[^" + q + r"\r\n]*[\d!#%^*+~])"          # a digit or symbol
        + r"|(?=[^" + q + r"\s]{12,}(?:" + q + r"|$))"        # one 12+ run, no spaces
        + r"|(?=[^" + q + r"\r\n]*(?-i:[a-z][A-Z])))"               # a case change inside a word
        # Ends at the closing quote or the end of the line (output can be cut mid-value), so a
        # value that stops at $ or { ("Bearer ${X}") is not taken.
        + r"([^" + q + r"\s<>{$][^" + q + r"\r\n<>{$]{5,})(?=" + q + r"|\r?\n|$)"
    )

def ident(classification, pattern, group=0, case_sensitive=True):
    d = {"classification": classification, "pattern": pattern, "caseSensitive": case_sensitive}
    if group:
        d["groupNumber"] = group
    d["identifierFilterStrategies"] = [{"strategy": "REDACT", "redactionFormat": FMT % classification}]
    return d

LABELLED = [
    # KEY=value  (shell, .env, ini, URLs' query strings)
    ident("secret-labelled-value", LABEL + r"[\"']?[ \t]*=[ \t]*(?![\"'])" + unquoted_value(True), 1, False),
    # key: value (YAML). No letters-only values: "model: ClassName" is YAML, not a secret.
    ident("secret-labelled-value", LABEL + r"[\"']?[ \t]*:[ \t]*(?![\"'])" + unquoted_value(False), 1, False),
    # key: "value", key = 'value', PHP 'key' => 'value', $cfg['key'] => 'value'
    ident("secret-labelled-value", LABEL + r"[\"']?\]?[ \t]*[:=>]{1,2}[ \t]*" + quoted_value('"'), 1, False),
    ident("secret-labelled-value", LABEL + r"[\"']?\]?[ \t]*[:=>]{1,2}[ \t]*" + quoted_value("'"), 1, False),
]

# npm auth: only the npmrc key itself (line start, or after "registry/:"), not DB_PASSWORD=.
NPM_AUTH = ident("secret-npm-auth",
                 r"(?<![A-Za-z0-9])(?:_authToken|_auth|_password)\s*=\s*(?![\"'$])"
                 r"(?![^\s]*" + PLACEHOLDER + r")([^\s\"'][^\s\"']{7,})", 1, False)

# JWT: header AND payload are base64url JSON objects, so both start with eyJ (gitleaks does the
# same). The old rule needed only the first part to.
JWT = ident("secret-jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

# ---------------------------------------------------------------------------
# 2. Built-in filter settings (identifiers.<filter> in policies/comprehensive.json).
#    ignoredPatterns are FULL matches against the span text (Phileas IgnoredPattern.matches
#    uses Matcher.matches()), case-sensitive unless (?i).
# ---------------------------------------------------------------------------
IP_IGNORED = [
    # Any run of hex groups joined only by "::" — Perl/PHP/Rust/C++ scope operators
    # (Digest::SHA -> "::", File::Path -> "e::", a::b::c), GitHub "::error::", plus ::1 and
    # fe80::1%en0. A real compressed address with a single ':' elsewhere (2001:db8::1)
    # does not fully match and stays redacted unless another rule below exempts it.
    r"(?i)[0-9a-f]{0,4}(?:::[0-9a-f]{0,4})+(?:%[\w.]+)?",
    # Private, loopback, link-local, CGNAT, unspecified, broadcast, documentation ranges.
    r"(?:10|127)(?:\.\d{1,3}){3}",
    r"192\.168(?:\.\d{1,3}){2}",
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}",
    r"169\.254(?:\.\d{1,3}){2}",
    r"100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])(?:\.\d{1,3}){2}",
    r"0\.0\.0\.0|255\.255\.255\.255",
    r"(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}",
    r"(?i)(?:fe80|f[cd][0-9a-f]{2}|2001:0?db8)(?::[0-9a-f]{0,4})*(?:%[\w.]+)?",
]

# Dev tools and products the name model takes for people. Whole-span match, so the common
# two-word forms ("Astro site", "the Husky hook") are covered by a pattern, not the term list.
TOOL_WORDS = [
    "Philter", "Husky", "Squid", "Astro", "Vite", "Vitest", "Jest", "Nuxt", "Remix", "Svelte",
    "SvelteKit", "Sanity", "Strapi", "Tina", "Prisma", "Pinia", "Zod", "Bun", "Deno", "Hugo",
    "Jekyll", "Gatsby", "Docusaurus", "Playwright", "Cypress", "Puppeteer", "Caddy", "Traefik",
    "Nginx", "Redis", "Postgres", "Homebrew", "Ansible", "Terraform", "Vagrant", "Jenkins",
    "Sentry", "Grafana", "Kibana", "Wrangler", "Forge", "Herd", "Craft", "Twig", "Blade",
    "Alpine", "Tailwind", "Laravel", "Symfony", "Coilpack", "Bedrock", "Sage", "Composer",
    "Gitleaks", "TruffleHog", "Presidio", "Phileas", "OrbStack", "Lando", "Mailpit", "Xdebug",
]
PERSON_IGNORED = [
    # A single all-lowercase token is a username, identifier or loop variable in tool output
    # (/Users/robert, "for n in", "owner robert"). Real names in data are capitalised or
    # come in pairs, which this does not match.
    r"[a-z][a-z0-9._-]*",
    # ls -l owner + group columns: "robert  staff".
    r"\S{1,64}[ \t]{1,16}(?:staff|wheel|admin|root|users|everyone|docker|www-data|_www|nogroup)",
    # Tool names, alone or with a following noun.
    r"(?i)(?:the\s+)?(?:" + "|".join(TOOL_WORDS) + r")(?:\s+(?:site|app|config|proxy|hook|hooks"
    r"|project|build|server|cli|docs|plugin|policy|set|container|image|cache|run|logs?))?",
]

BUILTIN_OVERRIDES = {
    "person": {
        "phEyeConfiguration": {"modelPath": "ph-eye-pii-en-small", "labels": ["name"], "threshold": 0.9},
        "ignored": TOOL_WORDS,
        "ignoredPatterns": [{"name": "person-%d" % i, "pattern": p} for i, p in enumerate(PERSON_IGNORED)],
        "phEyeFilterStrategies": [{"strategy": "REDACT"}],
    },
    # libphonenumber "possible number" hits get 0.95 only when the text is phone-formatted;
    # UUID chunks, CIDRs, hex alphabets and git's "-0500" get 0.60 (PhoneNumberRulesFilter).
    "phoneNumber": {
        "region": ["CA", "US"],
        "phoneNumberFilterStrategies": [{"condition": "confidence > 0.9", "strategy": "REDACT"}],
    },
    "ipAddress": {
        "ignoredPatterns": [{"name": "ip-%d" % i, "pattern": p} for i, p in enumerate(IP_IGNORED)],
        "ipAddressFilterStrategies": [{"strategy": "REDACT"}],
    },
    # Luhn: "4111 1111 1111 1112" was redacted.
    "creditCard": {"onlyValidCreditCardNumbers": True, "creditCardFilterStrategies": [{"strategy": "REDACT"}]},
}

# Policy-level ignoredPatterns: version-numbers must stop swallowing dotted quads (today every
# IPv4 span, public ones included, fully matches it and is ignored).
VERSION_NUMBERS = (
    r"\bv?(?!(?:\d{1,3}\.){3}\d{1,3}\b)(?!(?:1\.)?\(?\d{3}\)?\.\d{3}\.\d{4}(?!\w|\.\w))"
    r"\d+\.\d+\.\d+(?:[-+.][\w.]+)?\b"
)

# ---------------------------------------------------------------------------
# 3. The "code" variant used for tool output (policy code-<name>). Shape-only identifiers
#    with no label are dropped: in command output they match build ids, hashes and codes.
#    Their labelled forms (passport no. X, OHIP X, DL X, MRN X) stay.
# ---------------------------------------------------------------------------
CODE_OVERLAY = {
    "disableBuiltins": ["trackingNumber", "driversLicense", "vin", "age", "hospital"],
    "dropIdentifierPatterns": [
        r"\b[A-Z]{2}\d{6}\b",                    # passport-number, bare
        r"\b[A-Z]\d{8}\b",                       # passport-number, bare
        r"\b(?:\d{4}[- ]\d{3}[- ]\d{3}(?:[- ]?[A-Za-z]{2})?|\d{10}[- ]?[A-Za-z]{2})\b",  # health card, bare
        r"\b[A-Z]{4}[ ]?\d{4}[ ]?\d{4}\b",       # health card (RAMQ shape), bare
        r"\b[A-Z]\d{4}[- ]?\d{5}[- ]?\d{5}\b",   # drivers-licence, bare
        r"\b\d{5}[- ]\d{3}(?:[- ]\d{5,12})?\b",  # bank-account, bare
    ],
    "personThreshold": 0.92,
}


def emit():
    out = {
        "_about": "Generated by proposed.py. Paste-ready pieces; see 2026-11-23-low-fp-detection.md.",
        "policies/comprehensive.json": {
            "ignoredPatterns.version-numbers": VERSION_NUMBERS,
            "identifiers (built-in filters, replace these keys)": BUILTIN_OVERRIDES,
        },
        "library/api-keys.json": {
            "replace the four secret-labelled-value rules with": LABELLED,
            "replace secret-jwt with": JWT,
            "replace secret-npm-auth with": NPM_AUTH,
        },
        "policies/code-overlay.json": CODE_OVERLAY,
    }
    dest = pathlib.Path(__file__).with_suffix(".json")
    dest.write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {dest}")


if __name__ == "__main__":
    emit()
