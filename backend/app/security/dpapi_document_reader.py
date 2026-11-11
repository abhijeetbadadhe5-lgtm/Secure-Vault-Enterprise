
from pathlib import Path

from backend.app.database.encrypted_key_repository import (
    get_encrypted_key_record
)

from backend.app.security.kek_config import (
    validate_kek_id
)

from backend.app.security.windows_kek_store import (
    load_protected_kek
)

from backend.app.security.practice_document_service import (
    read_practice_document
)


class DocumentRecoveryError(Exception):
    """Generic error for document recovery failures."""


def read_document_with_dpapi(
    db_path,
    storage_dir,
    key_directory,
    document_id,
    owner_user_id
):
    """
    Recover an owned practice document using
    its KEK protected by Windows DPAPI.

    The caller does not supply the raw KEK.
    """

    # Reject invalid identity values.
    if type(document_id) is not int or document_id < 1:
        raise ValueError("Invalid document ID")

    if type(owner_user_id) is not int or owner_user_id < 1:
        raise ValueError("Invalid owner ID")

    # 1. Check document ownership first.
    record = get_encrypted_key_record(
        document_id=document_id,
        owner_user_id=owner_user_id,
        db_path=db_path
    )

    if record is None:
        raise LookupError("Document not found")

    # 2. Read the KEK identifier stored in SQLite.
    try:
        key_id = record["key_id"]
        validate_kek_id(key_id)

        # The key directory must already exist.
        # Do not create or replace any KEKs here.
        key_directory = Path(key_directory)

        if (
            not key_directory.is_dir()
            or key_directory.is_symlink()
        ):
            raise ValueError("Invalid key directory")

        # 3. Recover the existing KEK with Windows DPAPI.
        loaded = load_protected_kek(
            key_directory,
            key_id
        )

        kek = loaded["kek"]

        if type(kek) is not bytes or len(kek) != 32:
            raise ValueError("Invalid recovered KEK")

        # 4. Unwrap the DEK and decrypt the document
        # using the Lesson 47 encryption format.
        plaintext = read_practice_document(
            db_path=db_path,
            storage_dir=storage_dir,
            document_id=document_id,
            owner_user_id=owner_user_id,
            kek=kek
        )

        return plaintext

    except Exception:
        # Do not expose internal key-store,
        # decryption or filesystem error details.
        raise DocumentRecoveryError(
            "Document recovery failed"
        ) from None
