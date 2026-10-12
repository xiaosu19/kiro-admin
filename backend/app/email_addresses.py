"""Generate an address once during admission, then persist it with the user."""

import re
import secrets
import string


def generated_email(username):
    # Keep the local part within 64 characters, even for long SSO usernames.
    prefix = re.sub(r"[^a-zA-Z0-9_-]", "-", username).strip("-_")[:64] or "sso"
    length = 8 + secrets.randbelow(5)
    domain = "".join(secrets.choice(string.ascii_lowercase) for _ in range(length))
    return f"{prefix}@{domain}.com"
