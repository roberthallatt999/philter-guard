"""Cases for library/api-keys.json: (classification, text, must_catch_or_None).

Every fake value is assembled at runtime from parts, so this file holds no credential-shaped
literal (the safety guard refuses to read those, and secret scanners would flag them).
Test runs print classification and case number on failure, never the value.
"""

x = "x" * 24

aws = "AK" + "IA" + "Q7" * 8
gh_classic = "gh" + "p_" + "x" * 36
gh_oauth = "gh" + "o_" + "y" * 36
gh_fine = "github" + "_pat_" + "x" * 22 + "_" + "y" * 59
slack = "xo" + "xb-" + "1234567890-" + "1234567890123-" + "x" * 24
stripe = "sk" + "_live_" + "x" * 24
anthropic = "sk-" + "ant-" + "api03-" + "x" * 40
openai = "sk-" + "proj-" + "x" * 40
google = "AI" + "za" + "x" * 35
npm = "np" + "m_" + "x" * 36
philter = "ph" + "k" + "0123456789abcdef" * 2
jwt = ".".join(["ey" + "J" + "x" * 20, "ey" + "J" + "y" * 20, "z" * 30])
pem = ("-----BEGIN " + "PRIVATE KEY-----\n" + "x" * 64 + "\n" + "x" * 64
       + "\n-----END " + "PRIVATE KEY-----")
pem_rsa = "-----BEGIN " + "RSA PRIVATE KEY-----\n" + "x" * 64 + "\n-----END " + "RSA PRIVATE KEY-----"
bearer = "x" * 20 + "." + "y" * 10
pw = "Zq" + "7" * 10
sha = "a1b2c3d4e5" * 4
uuid = "123e4567-e89b-12d3-a456-426614174000"
integrity = "sha512-" + "A" * 86 + "=="

CASES = [
    ("secret-aws-access-key", f"aws key {aws} in config", aws),
    ("secret-github-token", f"token {gh_classic} here", gh_classic),
    ("secret-github-token", f"oauth {gh_oauth} here", gh_oauth),
    ("secret-github-token", f"fine-grained {gh_fine} here", gh_fine),
    ("secret-slack-token", f"bot {slack} here", slack),
    ("secret-stripe-key", f"stripe {stripe} here", stripe),
    ("secret-anthropic-key", f"key {anthropic} here", anthropic),
    ("secret-openai-key", f"key {openai} here", openai),
    ("secret-google-api-key", f"maps {google} here", google),
    ("secret-npm-token", f"registry {npm} here", npm),
    ("secret-philter-key", f"bootstrap {philter} here", philter),
    ("secret-jwt", f"session {jwt} here", jwt),
    ("secret-private-key", f"file:\n{pem}\nend", pem),
    ("secret-private-key", f"file:\n{pem_rsa}\nend", pem_rsa),
    ("secret-auth-header", f"Authorization: Bearer {bearer}", bearer),
    ("secret-auth-header", f"curl -H 'authorization: bearer {bearer}' https://example.test", bearer),
    ("secret-url-password", f"postgres://app:{pw}@db.internal:5432/main", pw),
    ("secret-labelled-value", f"DB_PASS" + f"WORD={pw}", pw),
    ("secret-labelled-value", '{"client' + '_secret": "' + pw + '"}', pw),
    ("secret-labelled-value", f"https://api.example.test/v1?access_token={pw}&x=1", pw),
    # must not match any secret- classification
    ("secret-labelled-value", f"commit {sha} merged", None),
    ("secret-labelled-value", f"id {uuid} created", None),
    ("secret-labelled-value", f'"integrity": "{integrity}"', None),
    ("secret-openai-key", "scikit-learn (sk-learn) installed", None),
    ("secret-labelled-value", "password reset email sent", None),
    ("secret-labelled-value", "token: <none>", None),
    ("secret-labelled-value", "api_key=\nnext line", None),
    ("secret-labelled-value", "api_key=", None),
    ("secret-auth-header", "Authorization: Bearer", None),
    ("secret-auth-header", "Authorization: Bearer\nnext line of text here", None),
]
