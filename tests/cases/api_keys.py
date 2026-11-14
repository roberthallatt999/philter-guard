"""Cases for library/api-keys.json.

Every fake value is built at runtime from a prefix plus cycled characters, so no source
line holds a whole credential-shaped string. Structured forms are assembled from named parts.

Tuples: (classification, text, the exact value that must be caught, or None for "must not
match"). A must-not-match text is checked against every secret- classification.
"""


def fake(prefix, n, alphabet):
    """prefix followed by n characters cycled from alphabet."""
    return prefix + "".join(alphabet[i % len(alphabet)] for i in range(n))


ALNUM = "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xYz"
UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"
HEX = "0123456789abcdef"
URLSAFE = ALNUM + "_-"
MIXED = "aB3xK9!q"

# structured parts
DASHES = "-" * 5
PEM_KIND = "PRIVATE KEY"
PEM_BEGIN = f"{DASHES}BEGIN {PEM_KIND}{DASHES}"
PEM_END = f"{DASHES}END {PEM_KIND}{DASHES}"
PEM_LINE = fake("", 64, ALNUM + "+/")
SCHEME = "postgres"
DB_USER = "app"
DB_HOST = "db.internal"

PW = fake("", 12, MIXED)
PW_SLASH = fake("", 5, ALNUM) + "/" + fake("", 5, ALNUM)
LBL_ENV = "DB_" + "PASSWORD"
LBL_LOWER = "pass" + "word"
LBL_TOKEN = "tok" + "en"
EQ, COLON, DQ, SQ = "=", ": ", '"', "'"
LETTERS =fake("", 14, "aBdEfGhJkLmNp")
PUNCT = fake("", 4, "aBdE") + ";" + fake("", 4, "kLmN") + "," + fake("", 3, "pQr")
BEARER =fake("", 30, ALNUM)
JWT = ".".join([fake("eyJ", 20, URLSAFE), fake("", 24, URLSAFE), fake("", 24, URLSAFE)])
PEM_FULL = f"{PEM_BEGIN}\n{PEM_LINE}\n{PEM_LINE}\n{PEM_END}"
PEM_TRUNC = f"{PEM_BEGIN}\n{PEM_LINE}\n{PEM_LINE}"
SHA40 = fake("", 40, HEX)
UUID = "-".join(fake("", n, HEX) for n in (8, 4, 4, 4, 12))
INTEGRITY = fake("", 86, ALNUM + "+/")


def vendor(cls, value):
    return (cls, f"value {value} here", value)


CASES = [
    # --- must catch, one per form
    vendor("secret-aws-access-key", fake("AKIA", 16, UPPER)),
    vendor("secret-github-token", fake("ghp_", 36, ALNUM)),
    vendor("secret-github-token", fake("github_pat_", 40, ALNUM)),
    vendor("secret-slack-token", fake("xoxb-", 24, ALNUM)),
    vendor("secret-stripe-key", fake("sk_live_", 24, ALNUM)),
    vendor("secret-stripe-key", fake("sk_test_", 24, ALNUM)),
    vendor("secret-stripe-key", fake("rk_live_", 24, ALNUM)),
    vendor("secret-stripe-key", fake("rk_test_", 24, ALNUM)),
    vendor("secret-anthropic-key", fake("sk-ant-", 40, URLSAFE)),
    vendor("secret-openai-key", fake("sk-proj-", 40, URLSAFE)),
    vendor("secret-openai-key", fake("sk-svcacct-", 40, URLSAFE)),
    vendor("secret-openai-key", fake("sk-admin-", 40, URLSAFE)),
    vendor("secret-openai-key", fake("sk-", 48, ALNUM)),
    vendor("secret-google-api-key", fake("AIza", 35, URLSAFE)),
    vendor("secret-npm-token", fake("npm_", 36, ALNUM)),
    vendor("secret-philter-key", fake("sk_", 32, HEX)),
    vendor("secret-jwt", JWT),
    ("secret-private-key", f"key:\n{PEM_FULL}", PEM_FULL),
    ("secret-private-key", f"key:\n{PEM_TRUNC}\nok", PEM_TRUNC),
    ("secret-auth-header", f"Authorization: Bearer {BEARER}", BEARER),
    ("secret-url-password", f"{SCHEME}://{DB_USER}:{PW}@{DB_HOST}/appdb", PW),
    ("secret-url-password", f"{SCHEME.upper()}://{DB_USER}:{PW}@{DB_HOST}/appdb", PW),
    ("secret-url-password", f"{SCHEME}://{DB_USER}:{PW_SLASH}@{DB_HOST}/appdb", PW_SLASH),
    ("secret-labelled-value", f"DB_PASSWORD={PW}", PW),
    ("secret-labelled-value", f'{{"client_secret": "{PW}"}}', PW),
    ("secret-labelled-value", f"https://x.test/cb?access_token={PW}", PW),
    ("secret-labelled-value", f"https://x.test/cb?access_token={PW}&next=1", PW),
    ("secret-labelled-value", LBL_ENV + EQ + LETTERS, LETTERS),
    ("secret-labelled-value", LBL_LOWER + EQ + LETTERS + " and more words", LETTERS),
    ("secret-labelled-value", LBL_LOWER + EQ + DQ + PUNCT + DQ, PUNCT),
    ("secret-labelled-value", LBL_TOKEN + COLON + SQ + PUNCT + SQ, PUNCT),
    # --- must not match (checked against every secret- classification)
    ("secret-github-token", SHA40, None),
    ("secret-github-token", UUID, None),
    ("secret-github-token", f'"integrity": "sha512-{INTEGRITY}=="', None),
    ("secret-openai-key", "scikit-learn (sk-learn)", None),
    ("secret-openai-key", "sk-1", None),
    ("secret-labelled-value", "password reset email sent", None),
    ("secret-labelled-value", "token: <none>", None),
    ("secret-labelled-value", "api_key=\nnext line", None),
    ("secret-auth-header", "Authorization: Bearer", None),
    ("secret-philter-key", fake("id_", 32, HEX), None),
    ("secret-philter-key", fake("fk_", 32, HEX), None),
    ("secret-url-password", "https://example.com/a:b@c", None),
    ("secret-url-password", "https://example.com:8080/contact/me@example.org", None),
    ("secret-url-password", "https://example.com:8080?email=me@example.org", None),
    ("secret-url-password", "https://example.com:8080#me@example.org", None),
    # ordinary code and prose around the labels
    ("secret-labelled-value", "token = getToken()", None),
    ("secret-labelled-value", "password = os.environ['DB_PASSWORD']", None),
    ("secret-labelled-value", "password: Optional[str]", None),
    ("secret-labelled-value", "secret: process.env.SECRET", None),
    ("secret-labelled-value", "password: this.password,", None),
    ("secret-labelled-value", "token: TokenResponse", None),
    ("secret-labelled-value", "token: expired", None),
]
