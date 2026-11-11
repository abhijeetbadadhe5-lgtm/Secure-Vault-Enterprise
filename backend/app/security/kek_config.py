
import base64
import binascii
import os
import re


KEY_SIZE = 32

KEK_ID_VARIABLE = "SECUREVAULT_KEK_ID"
KEK_SECRET_VARIABLE = "SECUREVAULT_KEK_B64"

KEK_ID_PATTERN = re.compile(
    r"[A-Za-z0-9_-]{1,64}"
)


def validate_kek_id(key_id):
    """Validate a simple KEK identifier."""

    if not isinstance(key_id, str):
        raise ValueError("KEK ID must be text")

    if KEK_ID_PATTERN.fullmatch(key_id) is None:
        raise ValueError(
            "KEK ID must contain 1 to 64 letters, "
            "numbers, underscores or hyphens"
        )

    return key_id


def decode_kek(encoded_key):
    """Decode and validate a Base64 AES-256 KEK."""

    if not isinstance(encoded_key, str):
        raise ValueError("Encoded KEK must be text")

    try:
        encoded_bytes = encoded_key.encode("ascii")

        kek = base64.b64decode(
            encoded_bytes,
            validate=True
        )

    except (UnicodeEncodeError, binascii.Error):
        raise ValueError(
            "KEK must use valid Base64 encoding"
        ) from None

    if len(kek) != KEY_SIZE:
        raise ValueError(
            "Decoded KEK must contain exactly 32 bytes"
        )

    # Require one standard, canonical Base64 representation.
    if base64.b64encode(kek).decode("ascii") != encoded_key:
        raise ValueError(
            "KEK must use canonical Base64 encoding"
        )

    return kek


def load_kek_from_environment():
    """
    Load a KEK and its identifier from environment variables.

    Does not generate, save or print a KEK.
    """

    key_id = os.environ.get(KEK_ID_VARIABLE)

    encoded_key = os.environ.get(
        KEK_SECRET_VARIABLE
    )

    if not key_id:
        raise RuntimeError(
            "SECUREVAULT_KEK_ID is not configured"
        )

    if not encoded_key:
        raise RuntimeError(
            "SECUREVAULT_KEK_B64 is not configured"
        )

    try:
        validated_id = validate_kek_id(key_id)

        kek = decode_kek(encoded_key)

    except ValueError as error:
        raise RuntimeError(
            "Invalid KEK configuration"
        ) from error

    return {
        "key_id": validated_id,
        "kek": kek
    }
