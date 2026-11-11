
from backend.app.security.kek_config import (
    validate_kek_id
)

from backend.app.security.encrypted_storage import (
    validate_storage_id
)

from backend.app.security.key_wrapping import (
    unwrap_dek
)

from backend.app.security.windows_kek_store import (
    load_protected_kek
)


class KEKRecoveryError(Exception):
    """A document key could not be recovered safely."""


def recover_document_key(
    key_directory,
    wrapped_record,
    owner_user_id,
    storage_id
):
    """
    Recover a document encryption key (DEK).

    Uses a Windows-protected KEK and AES-GCM.

    Never creates, replaces, or saves a KEK.
    Never prints secret key material.
    """

    error_message = (
        "Document key recovery failed"
    )

    # STEP 1: Validate the record structure.
    if not isinstance(wrapped_record, dict):
        raise KEKRecoveryError(error_message)

    required_fields = {
        "key_id",
        "nonce",
        "wrapped_dek"
    }

    if not required_fields.issubset(
        wrapped_record.keys()
    ):
        raise KEKRecoveryError(error_message)

    # STEP 2: Validate input types and sizes.
    key_id = wrapped_record["key_id"]
    nonce = wrapped_record["nonce"]
    wrapped_dek = wrapped_record["wrapped_dek"]

    try:
        validate_kek_id(key_id)
        validate_storage_id(storage_id)

        if (
            type(owner_user_id) is not int
            or owner_user_id < 1
        ):
            raise ValueError("Invalid owner")

        if not isinstance(nonce, bytes):
            raise ValueError("Invalid nonce")

        if len(nonce) != 12:
            raise ValueError("Invalid nonce length")

        if not isinstance(wrapped_dek, bytes):
            raise ValueError("Invalid wrapped DEK")

        if len(wrapped_dek) != 48:
            raise ValueError(
                "Invalid wrapped DEK length"
            )

    except (ValueError, TypeError):
        raise KEKRecoveryError(
            error_message
        ) from None

    # STEP 3: Load the existing protected KEK.
    try:
        loaded = load_protected_kek(
            key_directory,
            key_id
        )

    except Exception:
        # Do not expose OS errors or sensitive details.
        # Never generate a replacement key here.
        raise KEKRecoveryError(
            error_message
        ) from None

    # STEP 4: Authenticate and recover the DEK.
    try:
        dek = unwrap_dek(
            wrapped_dek,
            nonce,
            loaded["kek"],
            owner_user_id,
            storage_id
        )

    except Exception:
        # Wrong KEK, owner, storage ID, or tampering.
        raise KEKRecoveryError(
            error_message
        ) from None

    return dek
