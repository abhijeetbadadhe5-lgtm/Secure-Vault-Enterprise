
from pathlib import Path

from backend.app.security.kek_config import (
    validate_kek_id
)

from backend.app.security.windows_kek_store import (
    load_protected_kek
)

from backend.app.security.practice_document_service import (
    save_practice_document
)

from backend.app.security.dpapi_document_reader import (
    read_document_with_dpapi
)


class ProtectedKeyUnavailable(Exception):
    """The protected practice KEK could not be loaded."""


def _load_existing_practice_kek(key_directory, key_id):
    """
    Load a KEK already protected using Windows DPAPI.

    Never creates, rotates or replaces the KEK.
    """

    try:
        validate_kek_id(key_id)

        key_directory = Path(key_directory)

        if (
            not key_directory.is_dir()
            or key_directory.is_symlink()
        ):
            raise ValueError("Invalid key directory")

        loaded = load_protected_kek(
            key_directory,
            key_id
        )

        kek = loaded["kek"]

        if type(kek) is not bytes or len(kek) != 32:
            raise ValueError("Invalid protected key")

        return kek

    except Exception:
        raise ProtectedKeyUnavailable(
            "Protected practice key unavailable"
        ) from None


def save_document_with_dpapi(
    db_path,
    storage_dir,
    key_directory,
    document_id,
    owner_user_id,
    filename,
    plaintext,
    key_id
):
    """
    Save a practice document using an existing DPAPI KEK.

    The caller supplies a key ID, not raw KEK bytes.
    """

    # 1. Recover the existing KEK.
    kek = _load_existing_practice_kek(
        key_directory,
        key_id
    )

    # 2. Encrypt content, store the .svenc file,
    # and save its wrapped DEK in SQLite.
    storage_id = save_practice_document(
        db_path=db_path,
        storage_dir=storage_dir,
        document_id=document_id,
        owner_user_id=owner_user_id,
        filename=filename,
        plaintext=plaintext,
        kek=kek,
        key_id=key_id
    )

    return storage_id


def recover_document_with_dpapi(
    db_path,
    storage_dir,
    key_directory,
    document_id,
    owner_user_id
):
    """
    Recover a saved document.

    Uses SQLite to find its original key ID, then
    retrieves the corresponding KEK through DPAPI.
    """

    return read_document_with_dpapi(
        db_path=db_path,
        storage_dir=storage_dir,
        key_directory=key_directory,
        document_id=document_id,
        owner_user_id=owner_user_id
    )
