
from backend.app.security.hashing import calculate_sha256


def inspect_document(data: bytes) -> dict:
    """Return basic information about document bytes."""

    return {
        "size_bytes": len(data),
        "sha256": calculate_sha256(data)
    }
