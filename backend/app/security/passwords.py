
from argon2 import PasswordHasher
from argon2.exceptions import (
    VerificationError,
    InvalidHashError
)


password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Create an Argon2id password hash."""

    return password_hasher.hash(password)


def verify_password(
    stored_hash: str,
    password: str
) -> bool:
    """Check whether the password is correct."""

    try:
        return password_hasher.verify(
            stored_hash,
            password
        )

    except (VerificationError, InvalidHashError):
        return False
