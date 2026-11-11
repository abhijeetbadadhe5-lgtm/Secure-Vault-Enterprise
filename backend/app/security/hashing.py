
import hashlib


def calculate_sha256(data: bytes) -> str:
    """Return the SHA-256 hash of binary data."""
    return hashlib.sha256(data).hexdigest()
