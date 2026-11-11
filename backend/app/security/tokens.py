
import os
from datetime import datetime, timedelta, timezone

import jwt


ALGORITHM = "HS256"
ISSUER = "securevault-local"
TOKEN_LIFETIME_MINUTES = 15


def get_token_secret():
    """Read the token signing key from the environment."""

    secret = os.environ.get("SECUREVAULT_JWT_SECRET", "")

    if len(secret) < 32:
        raise RuntimeError(
            "SECUREVAULT_JWT_SECRET must contain "
            "at least 32 characters."
        )

    return secret


def create_access_token(user_id, lifetime_seconds=900):
    """Create a signed, expiring JWT."""

    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user_id),
        "iss": ISSUER,
        "iat": now,
        "exp": now + timedelta(seconds=lifetime_seconds)
    }

    return jwt.encode(
        payload,
        get_token_secret(),
        algorithm=ALGORITHM
    )


def decode_access_token(token):
    """Verify a JWT and return its user ID."""

    payload = jwt.decode(
        token,
        get_token_secret(),
        algorithms=[ALGORITHM],
        issuer=ISSUER,
        options={"require": ["sub", "iss", "exp"]}
    )

    user_id = int(payload["sub"])

    if user_id < 1:
        raise ValueError("Invalid user ID")

    return user_id
