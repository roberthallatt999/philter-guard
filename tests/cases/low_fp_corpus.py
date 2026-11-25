"""Corpus for the low-false-positive proposal (docs/proposals/2026-11-23-low-fp-detection.md).

Used by tests/test_low_fp.py, not by tests/test_patterns.py (it holds span-level cases for
built-in filters, which that runner has no notion of). Like api_keys.py, every fake secret is
built at runtime so no source line holds a whole credential-shaped string.

The must-not-match lines are real tool output that was redacted on 2026-11-23.
"""
import base64
import json

# tests/test_patterns.py loads every file here and reads CASES; this corpus has its own runner.
CASES = []


def fake(prefix, n, alphabet):
    return prefix + "".join(alphabet[i % len(alphabet)] for i in range(n))


def b64url(obj):
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


ALNUM = "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYz"
MIXED = "aB3xK9!q"
PW = fake("", 12, MIXED)
PW2 = fake("", 16, ALNUM)
LETTERS16 = fake("", 16, "AbcdefGhijkLmnop")
PWD = "pass" + "word"
TOK = "tok" + "en"
APIKEY = "api" + "_key"
JWT = ".".join([b64url({"alg": "HS256", "typ": "JWT"}), b64url({"sub": "1234567890", "iat": 1516239022}),
                fake("", 43, ALNUM + "_-")])

# (classification, text, exact value that must be caught)
SECRET_TP = [
    ("secret-labelled-value", f"DB_{PWD.upper()}={PW}", PW),
    ("secret-labelled-value", f'{PWD}: "{PW}"', PW),
    ("secret-labelled-value", f"{APIKEY} = '{PW2}'", PW2),
    ("secret-labelled-value", f'"client_secret": "{PW2}"', PW2),
    ("secret-labelled-value", f"secret_key: {PW2}", PW2),
    ("secret-labelled-value", f"$config['{PWD}'] => '{PW}',", PW),
    ("secret-labelled-value", f'{TOK} = "{LETTERS16}"', LETTERS16),       # letters only, 16, no spaces
    ("secret-labelled-value", f"export GITHUB_{TOK.upper()}={PW2}", PW2),
    ("secret-jwt", f"Authorization header carried {JWT} here", JWT),
]

# Must match no secret- rule at all (each line is checked against every one).
SECRET_FP = [
    "      GH_TOKEN: ai-egress-placeholder",
    "      - ${EGRESS_DIR}/cloudflare/api-token:/home/node/.config/cps-cloudflare/api-token:ro",
    "      - ${HOME}/.cache/cps-devcontainer/relay/tokens/site.token:/run/relay.token:ro",
    "      PHILTER_BOOTSTRAP_API_KEY: ${PHILTER_BOOTSTRAP_API_KEY:?missing in .env}",
    '      PHILTER_API_KEY: "Bearer ${PHILTER_BOOTSTRAP_API_KEY}"',
    "      GH_TOKEN: ${{ secrets.GH_TOKEN }}",
    "      token: ${{ github.token }}",
    f"{PWD}: required|min:8",
    f'"{PWD}": "string"',
    f'{TOK} = request.headers.get("x-auth")',
    f'{APIKEY} = os.environ["API_KEY"]',
    f'{PWD}: "Enter your {PWD}"',
    f"TOKEN=$(gh auth {TOK})",
    "secret=$SECRET",
    f"DB_{PWD.upper()}=your-{PWD}-here",
    f'{PWD} = "<your {PWD}>"',
    f"{TOK}_path=/var/run/secrets/{TOK}",
    f"{APIKEY}: ./config/{APIKEY}.txt",
    f"{TOK}: ~/.config/gh/hosts.yml",
    f'f"      GH_TOKEN: {{EGRESS_PLACEHOLDER}}",',
    "use Digest::SHA qw(sha256_hex);",
    "use IO::Socket::INET;",
    "use File::Path qw(make_path);",
    "POSIX::setsid() or die;",
    "cd /private/tmp/claude-501/x/1e600fe4-5651-43bc-a624-aa1f9d007745/scratchpad",
    "acl private_dst dst 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16",
    "-rw-r--r--@  1 robert  staff  8196 Nov 22 16:23 .DS_Store",
    "commit a2ab8fb  Date: Mon Nov 23 10:00:00 2026 -0500",
    "uuid 550e8400-e29b-41d4-a716-446655440000 sha 345a793",
    'HEX = "0123456789abcdef"',
]

# Span-level cases for built-in filters. Each is a span Philter produced (or should produce)
# and whether the proposed per-filter ignoredPatterns must ignore it. Full-match semantics.
#   (filter, span text, must_ignore)
SPAN_CASES = [
    # streetAddress — a test log's "exits 0" + next line read as "0 Pass Dr…" (2026-11-24)
    ("streetAddress", "0\n  PASS  dry run", True), ("streetAddress", "0 PASS dry run", True),
    ("streetAddress", "42 Wallaby Way", False), ("streetAddress", "123 Main Street", False),
    ("streetAddress", "100 Queen St W", False),
    # ipAddress — observed spans from Perl, PHP, GitHub workflow commands
    ("ipAddress", "::", True), ("ipAddress", "e::", True), ("ipAddress", "::add", True),
    ("ipAddress", "a::b", True), ("ipAddress", "::ba", True), ("ipAddress", "1::", True),
    ("ipAddress", "d::", True), ("ipAddress", "::1", True), ("ipAddress", "fe80::1%en0", True),
    ("ipAddress", "10.0.0.0", True), ("ipAddress", "192.168.0.0", True), ("ipAddress", "172.16.0.0", True),
    ("ipAddress", "169.254.0.0", True), ("ipAddress", "127.0.0.1", True), ("ipAddress", "100.64.0.1", True),
    ("ipAddress", "2001:db8::1", True), ("ipAddress", "203.0.113.7", True),
    # public addresses stay redacted
    ("ipAddress", "8.8.8.8", False), ("ipAddress", "142.250.72.14", False), ("ipAddress", "172.32.0.1", False),
    ("ipAddress", "2a03:2880:f12f:83:face:b00c:0:25de", False), ("ipAddress", "2606:4700::1111", False),
    # person — observed false positives
    ("person", "robert", True), ("person", "robert  staff", True), ("person", "n", True),
    ("person", "Husky", True), ("person", "Astro", True), ("person", "Astro site", True),
    ("person", "The Astro site", True), ("person", "Squid", True), ("person", "Philter", True),
    ("person", "Squid proxy", True),
    # person — real names stay redacted
    ("person", "Jane Doe", False), ("person", "Robert", False), ("person", "Robert Hallatt", False),
    ("person", "Marie Tremblay", False), ("person", "John Smith", False), ("person", "Miles Dyson", False),
]

# Confidences Philter reported via explain_redactions on 2026-11-23 (policy comprehensive).
#   (filter, span, confidence, is_real)
OBSERVED = [
    ("phoneNumber", "4-5651-43", 0.60, False),          # UUID path segment
    ("phoneNumber", "192.168.0.0/16", 0.60, False),
    ("phoneNumber", "169.254.0.0/16", 0.60, False),
    ("phoneNumber", "00 2026 -0500", 0.60, False),      # git log Date line
    ("phoneNumber", "0123456789", 0.60, False),         # hex alphabet in a test file
    ("phoneNumber", "613-555-0142", 0.95, True),
    ("phoneNumber", "(416) 555-0199", 0.95, True),
    ("phoneNumber", "+1 902 555 0123", 0.95, True),
    ("person", "robert  staff", 0.879, False),
    ("person", "robert  staff", 0.825, False),
    ("person", "Husky", 0.847, False),
    ("person", "John Smith", 0.962, True),
    ("person", "Miles Dyson", 0.975, True),
    ("person", "Jane Doe", 0.985, True),
    ("person", "Robert", 0.987, True),
    ("person", "Marie Tremblay", 0.988, True),
    ("person", "Robert Hallatt", 0.993, True),
]

# version-numbers ignore (policy-level): (text, must_fully_match)
VERSION_CASES = [
    ("4.0.1", True), ("v1.14.0", True), ("10.0.19041.1", True), ("3.4.2-beta.1", True),
    ("8.8.8.8", False), ("203.0.113.7", False), ("192.168.1.10", False),
]
