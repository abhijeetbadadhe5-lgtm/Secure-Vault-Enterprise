
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.app.security.encrypted_storage import (
    validate_storage_id
)


KEY_SIZE = 32
WRAP_NONCE_SIZE = 12


def make_wrapping_context(owner_user_id, storage_id):
    """
    Create authenticated context for one document key.

    The owner and storage ID must match during unwrapping.
    """

    if type(owner_user_id) is not int or owner_user_id < 1:
        raise ValueError("Invalid owner user ID")

    validate_storage_id(storage_id)

    return (
        f"securevault-dek-wrap-v1:{owner_user_id}:{storage_id}"
    ).encode("utf-8")


def check_key(key, name):
    """Require a 256-bit key."""

    if not isinstance(key, bytes):
        raise ValueError(f"{name} must be bytes")

    if len(key) != KEY_SIZE:
        raise ValueError(f"{name} must contain 32 bytes")


def generate_kek():
    """Generate a random AES-256 key-encryption key."""

    return AESGCM.generate_key(bit_length=256)


def wrap_dek(
    dek,
    kek,
    owner_user_id,
    storage_id
):
    """
    Encrypt a document encryption key using the KEK.

    This function does not write anything to disk.
    """

    check_key(dek, "DEK")
    check_key(kek, "KEK")

    context = make_wrapping_context(
        owner_user_id,
        storage_id
    )

    nonce = os.urandom(WRAP_NONCE_SIZE)

    wrapped_dek = AESGCM(kek).encrypt(
        nonce,
        dek,
        context
    )

    return {
        "nonce": nonce,
        "wrapped_dek": wrapped_dek
    }


def unwrap_dek(
    wrapped_dek,
    nonce,
    kek,
    owner_user_id,
    storage_id
):
    """
    Recover a DEK using the correct KEK and context.

    AES-GCM authentication detects incorrect keys
    or altered wrapped-key data.
    """

    check_key(kek, "KEK")

    if not isinstance(nonce, bytes):
        raise ValueError("Nonce must be bytes")

    if len(nonce) != WRAP_NONCE_SIZE:
        raise ValueError("Nonce must contain 12 bytes")

    if not isinstance(wrapped_dek, bytes):
        raise ValueError("Wrapped DEK must be bytes")

    if len(wrapped_dek) != KEY_SIZE + 16:
        raise ValueError("Invalid wrapped DEK length")

    context = make_wrapping_context(
        owner_user_id,
        storage_id
    )

    dek = AESGCM(kek).decrypt(
        nonce,
        wrapped_dek,
        context
    )

    check_key(dek, "Recovered DEK")

    return dek
