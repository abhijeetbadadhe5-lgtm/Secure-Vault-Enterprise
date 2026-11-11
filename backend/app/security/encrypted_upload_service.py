
import sqlite3

from contextlib import closing
from pathlib import Path

from backend.app.security.encrypted_upload_preflight import (
    prepare_encrypted_upload
)

from backend.app.security.persistent_practice_vault import (
    save_document_with_dpapi
)


class EncryptedUploadServiceError(Exception):
    """Encrypted upload preparation or storage failed."""


class UploadOwnershipError(LookupError):
    """The owned document was not found."""


def _require_directory(directory):
    """
    Require an existing directory.

    Do not create or replace storage directories.
    """

    path = Path(directory)

    if path.is_symlink() or not path.is_dir():
        raise EncryptedUploadServiceError(
            "Trusted storage directory unavailable"
        )

    return path


def _get_owned_filename(
    db_path,
    document_id,
    authenticated_owner_id
):
    """
    Check document ownership using SQLite.

    Return the existing document filename.

    This function never creates database records.
    """

    database = Path(db_path)

    if database.is_symlink() or not database.is_file():
        raise EncryptedUploadServiceError(
            "Existing database unavailable"
        )

    try:
        # Open the existing database in read-only mode.
        database_uri = (
            database.resolve().as_uri()
            + "?mode=ro"
        )

        with closing(
            sqlite3.connect(
                database_uri,
                uri=True
            )
        ) as connection:

            row = connection.execute(
                """
                SELECT filename
                FROM owned_documents
                WHERE id = ?
                  AND owner_user_id = ?
                """,
                (
                    document_id,
                    authenticated_owner_id
                )
            ).fetchone()

    except sqlite3.Error:
        raise EncryptedUploadServiceError(
            "Document ownership check failed"
        ) from None

    if row is None:
        raise UploadOwnershipError(
            "Document not found"
        )

    return row[0]


def store_encrypted_upload(
    db_path,
    storage_dir,
    key_directory,
    document_id,
    authenticated_owner_id,
    filename,
    content,
    key_id
):
    """
    Validate, authorize and persist encrypted content.

    IMPORTANT:
    authenticated_owner_id must come from a
    verified backend authentication dependency.

    Do not accept a user-supplied owner ID directly.

    This service requires an existing owned_documents
    record and an existing DPAPI-protected KEK.

    It does not create users or document metadata.
    """

    # Step 1: Validate identity and document IDs.
    if (
        type(authenticated_owner_id) is not int
        or authenticated_owner_id <= 0
        or type(document_id) is not int
        or document_id <= 0
    ):
        raise EncryptedUploadServiceError(
            "Invalid upload context"
        )

    # Step 2: Validate content and safe filename.
    try:
        summary = prepare_encrypted_upload(
            filename=filename,
            content=content,
            owner_user_id=authenticated_owner_id,
            document_id=document_id
        )

    except ValueError:
        raise EncryptedUploadServiceError(
            "Encrypted upload validation failed"
        ) from None

    # Step 3: Require trusted pre-existing directories.
    storage_path = _require_directory(
        storage_dir
    )

    key_path = _require_directory(
        key_directory
    )

    # Step 4: Verify ownership in SQLite.
    existing_filename = _get_owned_filename(
        db_path=db_path,
        document_id=document_id,
        authenticated_owner_id=authenticated_owner_id
    )

    # The filename is bound to existing metadata.
    # Do not allow a mismatch.
    if existing_filename != summary["filename"]:
        raise EncryptedUploadServiceError(
            "Document filename mismatch"
        )

    # Step 5: Use the existing Lesson 49 service.
    # It recovers the existing KEK using DPAPI,
    # generates a fresh DEK, encrypts content,
    # and stores encrypted metadata.
    try:
        storage_id = save_document_with_dpapi(
            db_path=db_path,
            storage_dir=storage_path,
            key_directory=key_path,
            document_id=document_id,
            owner_user_id=authenticated_owner_id,
            filename=summary["filename"],
            plaintext=content,
            key_id=key_id
        )

    except Exception:
        raise EncryptedUploadServiceError(
            "Encrypted upload storage failed"
        ) from None

    # Never return document plaintext or raw keys.
    return {
        "stored": True,
        "document_id": document_id,
        "owner_user_id": authenticated_owner_id,
        "filename": summary["filename"],
        "size_bytes": summary["size_bytes"],
        "storage_id": storage_id,
        "encrypted": True
    }
