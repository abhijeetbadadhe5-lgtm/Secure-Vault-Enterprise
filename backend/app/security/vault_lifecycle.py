"""SecureVault safe metadata mutation and encrypted-document deletion.

No database creation, no key generation. All operations require an existing
SQLite database. This module is intended for the local single-process MVP.
"""
import os
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path

from backend.app.security.encrypted_storage import validate_storage_id


class VaultLifecycleError(Exception):
    """A requested vault mutation cannot safely complete."""


class EncryptedRenameBlocked(VaultLifecycleError):
    """Renaming ciphertext-bound filename metadata requires re-encryption."""


def _verify_ids(document_id, owner_user_id):
    if type(document_id) is not int or document_id <= 0:
        raise ValueError("Invalid document ID")
    if type(owner_user_id) is not int or owner_user_id <= 0:
        raise ValueError("Invalid owner ID")


def _existing_database(db_path):
    path = Path(db_path)
    if not path.is_file():
        raise VaultLifecycleError("Existing database is required")
    return path


def _has_encrypted_key_table(db):
    """Check whether the existing database supports encrypted keys."""
    return db.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type = 'table'
          AND name = 'encrypted_document_keys'
        LIMIT 1
        """
    ).fetchone() is not None



def reject_encrypted_rename(document_id, owner_user_id, db_path):
    """Fail closed if a document has an encrypted-key record.

    Filename is part of the encrypted document's authenticated context.
    Changing only the metadata would break recovery.
    """
    _verify_ids(document_id, owner_user_id)
    path = _existing_database(db_path)
    # Read-only connection; never create the DB during a preflight.
    
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        if not _has_encrypted_key_table(db):
            return

        row = db.execute(

            """SELECT 1 FROM encrypted_document_keys AS k
               JOIN owned_documents AS d ON d.id = k.document_id
               WHERE d.id=? AND d.owner_user_id=? LIMIT 1""",
            (document_id, owner_user_id),
        ).fetchone()
    if row is not None:
        raise EncryptedRenameBlocked("Encrypted documents cannot be renamed without re-encryption")


def _existing_storage_file(storage_dir, storage_id):
    if not isinstance(storage_dir, (str, Path)):
        raise VaultLifecycleError("Encrypted storage configuration is required")
    root = Path(storage_dir)
    if not root.is_dir() or root.is_symlink():
        raise VaultLifecycleError("Encrypted storage directory unavailable")
    # Use the same identifier validator as SecureVault encrypted storage.
    validate_storage_id(storage_id)
    root_real = root.resolve(strict=True)
    source = root / (storage_id + ".svenc")
    if not source.is_file() or source.is_symlink():
        raise VaultLifecycleError("Expected encrypted file is missing")
    if source.resolve(strict=True).parent != root_real:
        raise VaultLifecycleError("Encrypted file escapes configured storage")
    return source


def delete_owned_document_and_ciphertext(document_id, owner_user_id, db_path, storage_dir=None):
    """Remove an owned document and its ciphertext using a reversible stage.

    - Ownership check and SQLite mutations are within one IMMEDIATE transaction.
    - If encrypted, first move ciphertext to a same-directory staging file.
    - On SQL failure restore the original ciphertext name.
    - On successful commit remove the staged file.

    This is NOT crash-atomic across SQLite and NTFS. A power loss can leave a
    .pending-delete file. Do not treat this as a production-ready delete protocol.
    """
    _verify_ids(document_id, owner_user_id)
    path = _existing_database(db_path)
    staged = None
    original = None
    committed = False

    try:
        with closing(sqlite3.connect(path, timeout=10)) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            try:
                owned = db.execute(
                    "SELECT 1 FROM owned_documents WHERE id=? AND owner_user_id=?",
                    (document_id, owner_user_id),
                ).fetchone()
                if owned is None:
                    db.rollback()
                    return False

                
                key_row = None

                if _has_encrypted_key_table(db):
                    key_row = db.execute(
                        """
                        SELECT storage_id
                        FROM encrypted_document_keys
                        WHERE document_id = ?
                        """,
                        (document_id,),
                    ).fetchone()

                if key_row is not None:
                    original = _existing_storage_file(storage_dir, key_row[0])
                    staged = original.with_name(original.name + ".pending-delete-" + uuid.uuid4().hex)
                    if staged.exists():
                        raise VaultLifecycleError("Unable to stage encrypted file")
                    original.rename(staged)
                    db.execute("DELETE FROM encrypted_document_keys WHERE document_id=?", (document_id,))

                cursor = db.execute(
                    "DELETE FROM owned_documents WHERE id=? AND owner_user_id=?",
                    (document_id, owner_user_id),
                )
                if cursor.rowcount != 1:
                    raise VaultLifecycleError("Document changed during deletion")
                db.commit()
                committed = True
            except Exception:
                db.rollback()
                raise

        if staged is not None:
            try:
                staged.unlink()
            except OSError as exc:
                raise VaultLifecycleError(
                    "Metadata deleted; staged ciphertext needs administrator cleanup"
                ) from exc
        return True
    except Exception as exc:
        if not committed and staged is not None and original is not None and staged.exists():
            try:
                if not original.exists():
                    staged.rename(original)
            except OSError:
                raise VaultLifecycleError(
                    "Deletion interrupted; ciphertext restoration requires inspection"
                ) from None
        if isinstance(exc, VaultLifecycleError):
            raise
        raise VaultLifecycleError("Safe document deletion failed") from None
