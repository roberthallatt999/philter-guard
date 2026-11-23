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
DOTTED = fake("", 5, "abcde") + "." + fake("", 6, "fG3hJk")
PW_DIGSLASH = fake("", 4, "1234") + "/" + fake("", 5, "aBdEf")
SPACED = fake("", 6, "aBdEf") + " " + fake("", 6, "kLmNp")
PUNCT =fake("", 4, "aBdE") + ";" + fake("", 4, "kLmN") + "," + fake("", 3, "pQr")
BEARER =fake("", 30, ALNUM)
JWT = ".".join([fake("eyJ", 20, URLSAFE), fake("", 24, URLSAFE), fake("", 24, URLSAFE)])
PEM_FULL = f"{PEM_BEGIN}\n{PEM_LINE}\n{PEM_LINE}\n{PEM_END}"
PEM_TRUNC = f"{PEM_BEGIN}\n{PEM_LINE}\n{PEM_LINE}"
SHA40 = fake("", 40, HEX)
UUID = "-".join(fake("", n, HEX) for n in (8, 4, 4, 4, 12))
INTEGRITY = fake("", 86, ALNUM + "+/")

# framework config labels, each assembled from parts
L_DJANGO = "DJANGO_" + "SECRET" + "_KEY"
L_JWT = "JWT_" + "SECRET" + "_KEY"
L_FLASK = "SECRET" + "_KEY"
L_CRAFT = "CRAFT_" + "SECURITY" + "_KEY"
L_LARAVEL = "APP" + "_KEY"
L_DBPASS = "DB_" + "PASS"
L_DBPASS_LONG = "DATABASE_" + "PASS"
L_MYSQL_PWD = "MYSQL_" + "PWD"
L_WP_PASSWORD = "DB_" + "PASSWORD"
L_WP_KEY = "AUTH_" + "KEY"
L_WP_SALT = "SECURE_AUTH_" + "SALT"
L_WP_SECRET = "JWT_AUTH_" + "SECRET"
B64 = "base64:" + fake("", 32, ALNUM + "+/")
CWD = "/Users/someone/projects/site"
SHORT = fake("", 5, ALNUM)


def define(label, value):
    return "define( '" + label + "', '" + value + "' );"


def vendor(cls, value):
    return (cls, f"value {value} here", value)



# --- structured fakes for the 2026-11 vendor rules
OP_SK = "A3-" + "-".join([fake("", 6, UPPER), fake("", 6, UPPER)] + [fake("", 5, UPPER)] * 4)
SENDGRID = "S" + "G." + fake("", 22, URLSAFE) + "." + fake("", 43, URLSAFE)
POSTMAN = "PM" + "AK-" + fake("", 24, HEX) + "-" + fake("", 34, HEX)
MAPBOX = "s" + "k.eyJ" + fake("", 30, ALNUM) + "." + fake("", 22, ALNUM)
TELEGRAM = "123456789:A" + "A" + fake("", 33, URLSAFE)
SLACK_HOOK = "https://hooks.slack.com/services/" + fake("T", 8, UPPER) + "/" + fake("B", 8, UPPER) + "/" + fake("", 24, ALNUM)
DISCORD_HOOK = "https://discord.com/api/webhooks/123456789012345678/" + fake("", 60, URLSAFE)
AZ_KEY = fake("", 86, ALNUM + "+/") + "=="
COOKIE = "session=" + fake("", 32, ALNUM) + "; Path=/; HttpOnly"
PGP_KIND = "PGP PRIVATE KEY BLOCK"
PGP_BLOCK = f"{DASHES}BEGIN {PGP_KIND}{DASHES}\n\n{PEM_LINE}\n{DASHES}END {PGP_KIND}{DASHES}"

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
    ("secret-labelled-value", LBL_ENV + EQ + DOTTED, DOTTED),
    ("secret-url-password", f"{SCHEME}://{DB_USER}:{PW_DIGSLASH}@{DB_HOST}/appdb", PW_DIGSLASH),
    ("secret-labelled-value", LBL_LOWER + EQ + DQ + SPACED + DQ, SPACED),
    ("secret-labelled-value", LBL_TOKEN + COLON + SQ + LETTERS, LETTERS),
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
    ("secret-labelled-value", "password = this.password", None),
    ("secret-labelled-value", "secret = process.env.SECRET;", None),
    # --- framework config keys (P4): must catch, one per form, values from parts
    ("secret-labelled-value", L_DJANGO + EQ + PW, PW),
    ("secret-labelled-value", L_JWT + " " + EQ + " " + DQ + PW + DQ, PW),
    ("secret-labelled-value", L_FLASK + COLON + SQ + PW + SQ, PW),
    ("secret-labelled-value", L_CRAFT + EQ + PW, PW),
    ("secret-labelled-value", L_LARAVEL + EQ + B64, B64),
    ("secret-labelled-value", L_DBPASS + EQ + PW, PW),
    ("secret-labelled-value", L_DBPASS_LONG + EQ + DQ + PW + DQ, PW),
    ("secret-define-call", define(L_WP_PASSWORD, PW), PW),
    ("secret-define-call", define(L_WP_KEY, PW), PW),
    ("secret-define-call", define(L_WP_SALT, PW), PW),
    ("secret-define-call", define(L_WP_SECRET, PW), PW),
    # --- working-directory variables (P5)
    ("secret-labelled-value", L_MYSQL_PWD + EQ + PW, PW),
    ("secret-labelled-value", "PW" + "D" + EQ + CWD, None),
    ("secret-labelled-value", "OLD" + "PW" + "D" + EQ + CWD, None),
    ("secret-labelled-value", '{"pw' + 'd": "' + CWD + '"}', None),
    ("secret-labelled-value", L_MYSQL_PWD + EQ + CWD, None),
    # --- near misses that must stay unredacted (P4)
    ("secret-labelled-value", "by" + "pass" + EQ + PW, None),
    ("secret-labelled-value", "com" + "pass" + COLON + PW, None),
    ("secret-labelled-value", '{"com' + 'pass": "' + PW + '"}', None),
    ("secret-labelled-value", "PASS" + "WORD_MIN_LENGTH = 8", None),
    ("secret-labelled-value", "'pass" + "word_min_length' => 12", None),
    ("secret-labelled-value", '"pass' + 'word_min_length": 8', None),
    ("secret-define-call", define(L_WP_PASSWORD, SHORT), None),
    ("secret-define-call", define(L_WP_KEY, SHORT), None),
    ("secret-define-call", "define('WP_" + "DEBUG', true);", None),
    # --- vendor tokens added 2026-11 (values built at runtime)
    ("secret-gitlab-token", "CI uses " + fake("glp" + "at-", 20, URLSAFE), fake("glp" + "at-", 20, URLSAFE)),
    ("secret-gitlab-token", "see glpat-docs for details", None),
    ("secret-1password-token", "OP_SERVICE_ACCOUNT_" + "TOKEN " + fake("op" + "s_", 60, URLSAFE), fake("op" + "s_", 60, URLSAFE)),
    ("secret-1password-secret-key", "key " + OP_SK, OP_SK),
    ("secret-1password-secret-key", "model A3-turbo", None),
    ("secret-sendgrid-key", SENDGRID, SENDGRID),
    ("secret-mailgun-key", "auth " + fake("ke" + "y-", 32, HEX), fake("ke" + "y-", 32, HEX)),
    ("secret-mailgun-key", "the key-value store", None),
    ("secret-twilio-key", fake("S" + "K", 32, HEX), fake("S" + "K", 32, HEX)),
    ("secret-shopify-token", fake("shp" + "at_", 32, HEX), fake("shp" + "at_", 32, HEX)),
    ("secret-digitalocean-token", fake("do" + "p_v1_", 64, HEX), fake("do" + "p_v1_", 64, HEX)),
    ("secret-huggingface-token", fake("h" + "f_", 34, "aBcDeFgHjK"), fake("h" + "f_", 34, "aBcDeFgHjK")),
    ("secret-stripe-webhook-secret", fake("wh" + "sec_", 32, ALNUM), fake("wh" + "sec_", 32, ALNUM)),
    ("secret-square-token", fake("EA" + "AA", 60, URLSAFE), fake("EA" + "AA", 60, URLSAFE)),
    ("secret-vault-token", "VAULT_" + "TOKEN " + fake("hv" + "s.", 30, URLSAFE), fake("hv" + "s.", 30, URLSAFE)),
    ("secret-postman-key", POSTMAN, POSTMAN),
    ("secret-docker-token", fake("dckr" + "_pat_", 30, URLSAFE), fake("dckr" + "_pat_", 30, URLSAFE)),
    ("secret-pypi-token", fake("py" + "pi-AgEIcHlwaS5vcmc", 60, URLSAFE), fake("py" + "pi-AgEIcHlwaS5vcmc", 60, URLSAFE)),
    ("secret-sentry-token", fake("sntr" + "ys_", 60, ALNUM), fake("sntr" + "ys_", 60, ALNUM)),
    ("secret-mapbox-secret", MAPBOX, MAPBOX),
    ("secret-mapbox-secret", "public " + "pk.eyJ" + fake("", 30, ALNUM) + "." + fake("", 22, ALNUM), None),
    ("secret-telegram-bot-token", TELEGRAM, TELEGRAM),
    ("secret-atlassian-token", fake("ATA" + "TT3", 190, URLSAFE), fake("ATA" + "TT3", 190, URLSAFE)),
    ("secret-saas-token", fake("nt" + "n_", 46, ALNUM), fake("nt" + "n_", 46, ALNUM)),
    ("secret-saas-token", fake("sb" + "p_", 40, HEX), fake("sb" + "p_", 40, HEX)),
    # --- credentials inside URLs, headers, commands and key files
    ("secret-webhook-url", "post to " + SLACK_HOOK, SLACK_HOOK),
    ("secret-webhook-url", "post to " + DISCORD_HOOK, DISCORD_HOOK),
    ("secret-webhook-url", "docs at https://api.slack.com/messaging/webhooks", None),
    ("secret-signed-url", "GET https://b.s3.amazonaws.com/f.pdf?X-Amz-Expires=300&X-Amz-" + "Signature=" + fake("", 64, HEX), fake("", 64, HEX)),
    ("secret-azure-storage-key", "DefaultEndpointsProtocol=https;AccountName=app;Account" + "Key=" + AZ_KEY + ";", AZ_KEY),
    ("secret-cookie-header", "< Set-" + "Cookie: " + COOKIE, COOKIE),
    ("secret-cookie-header", "-H 'Cook" + "ie: " + COOKIE + "'", COOKIE),
    ("secret-cookie-header", "a cookie: chocolate", None),
    ("secret-curl-basic-auth", "curl -u " + "admin" + ":" + PW + " https://x.test", PW),
    ("secret-curl-basic-auth", "curl -u admin:$API_PASS https://x.test", None),
    ("secret-npm-auth", "//registry.npmjs.org/:_auth" + "Token=" + fake("", 36, ALNUM), fake("", 36, ALNUM)),
    ("secret-npm-auth", "//registry.npmjs.org/:_auth" + "Token=${NPM_TOKEN}", None),
    ("secret-pgp-private-key", PGP_BLOCK, PGP_BLOCK),
    ("secret-gcp-key-id", '{"private_key' + '_id": "' + fake("", 40, HEX) + '"}', fake("", 40, HEX)),
    # --- tokens whose last character is '-' (a trailing \\b would miss them)
    ("secret-sendgrid-key", SENDGRID[:-1] + "- next", SENDGRID[:-1] + "-"),
    ("secret-square-token", fake("EA" + "AA", 59, URLSAFE) + "- next", fake("EA" + "AA", 59, URLSAFE) + "-"),
    ("secret-telegram-bot-token", TELEGRAM[:-1] + "-", TELEGRAM[:-1] + "-"),
    ("secret-saas-token", fake("dp" + ".st.", 43, URLSAFE) + "- next", fake("dp" + ".st.", 43, URLSAFE) + "-"),
    # --- fixed-alphabet tokens followed by '-' must still be caught
    ("secret-saas-token", fake("lin" + "_api_", 40, ALNUM) + "-v2", fake("lin" + "_api_", 40, ALNUM)),
    ("secret-saas-token", fake("sb" + "p_", 40, HEX) + "-prod", fake("sb" + "p_", 40, HEX)),
    ("secret-saas-token", fake("nf" + "p_", 36, ALNUM) + "-x", fake("nf" + "p_", 36, ALNUM)),
    ("secret-saas-token", fake("nt" + "n_", 46, ALNUM) + "-x", fake("nt" + "n_", 46, ALNUM)),
]
