
import json
import re
import secrets
import sqlite3

from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM
)

from backend.app.database.encrypted_key_repository import (
    save_encrypted_key_record,
    get_encrypted_key_record
)

from backend.app.security.encrypted_storage import (
    validate_storage_id
)


def _validate_kek(kek):
    if type(kek) is not bytes or len(kek) != 32:
        raise ValueError("KEK must contain 32 bytes")


def _validate_filename(filename):
    if (
        type(filename) is not str
        or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.txt",
            filename
        ) is None
        or ".." in filename
    ):
        raise ValueError("Unsafe practice filename")


def _get_owned_filename(
    db_path,
    document_id,
    owner_user_id
):
    # Ensure we never silently create a new database.
    if not Path(db_path).is_file():
        raise FileNotFoundError("Database not found")

    with closing(
        sqlite3.connect(db_path)
    ) as connection:

        row = connection.execute(
            """
            SELECT filename
            FROM owned_documents
            WHERE id = ?
              AND owner_user_id = ?
            """,
            (document_id, owner_user_id)
        ).fetchone()

    if row is None:
        raise LookupError("Owned document not found")

    return row[0]


def _aad(kind, owner_id, document_id, storage_id,
         filename):
    # Authenticated context binds ciphertext to
    # its owner, document, storage ID and filename.
    return json.dumps(
        [
            "SecureVault-L47-v1",
            kind,
            owner_id,
            document_id,
            storage_id,
            filename
        ],
        separators=(",", ":")
    ).encode("utf-8")


def save_practice_document(
    db_path,
    storage_dir,
    document_id,
    owner_user_id,
    filename,
    plaintext,
    kek,
    key_id="lesson47-practice-v1"
):
    """
    Encrypt and store fictional practice content.

    Uses a caller-supplied, in-memory KEK.
    Does not modify existing document metadata.
    """

    _validate_kek(kek)
    _validate_filename(filename)

    if type(document_id) is not int or document_id < 1:
        raise ValueError("Invalid document ID")

    if type(owner_user_id) is not int or owner_user_id < 1:
        raise ValueError("Invalid owner ID")

    if type(plaintext) is not bytes or not plaintext:
        raise ValueError("Practice content must be bytes")

    if len(plaintext) > 1024 * 1024:
        raise ValueError("Practice content is too large")

    storage_dir = Path(storage_dir)

    if not storage_dir.is_dir() or storage_dir.is_symlink():
        raise ValueError("Trusted storage folder missing")

    # Confirm ownership and the canonical filename.
    actual_filename = _get_owned_filename(
        db_path,
        document_id,
        owner_user_id
    )

    if filename != actual_filename:
        raise ValueError("Filename does not match document")

    # Random file ID. Never use the original filename
    # as the encrypted storage filename.
    storage_id = secrets.token_hex(16)
    storage_path = storage_dir / f"{storage_id}.svenc"

    dek = AESGCM.generate_key(bit_length=256)

    file_nonce = secrets.token_bytes(12)

    encrypted_content = AESGCM(dek).encrypt(
        file_nonce,
        plaintext,
        _aad(
            "file",
            owner_user_id,
            document_id,
            storage_id,
            filename
        )
    )

    wrap_nonce = secrets.token_bytes(12)

    wrapped_dek = AESGCM(kek).encrypt(
        wrap_nonce,
        dek,
        _aad(
            "key",
            owner_user_id,
            document_id,
            storage_id,
            filename
        )
    )

    # Track whether this function created a new file.
    created = False

    try:
        # "xb" creates a file exclusively and refuses
        # to overwrite an existing one.
        with open(storage_path, "xb") as file:
            created = True
            file.write(file_nonce + encrypted_content)

        # Save the storage reference and wrapped DEK.
        # The repository checks document ownership.
        save_encrypted_key_record(
            document_id=document_id,
            owner_user_id=owner_user_id,
            storage_id=storage_id,
            key_id=key_id,
            wrap_nonce=wrap_nonce,
            wrapped_dek=wrapped_dek,
            db_path=db_path
        )

    except Exception:
        # If the SQLite write fails, remove only the
        # newly created practice encrypted file.
        if created:
            storage_path.unlink(missing_ok=True)
        raise

    return storage_id


def read_practice_document(
    db_path,
    storage_dir,
    document_id,
    owner_user_id,
    kek
):
    """
    Retrieve and decrypt an owned practice document.

    Requires the same 32-byte KEK used when saving.
    """

    _validate_kek(kek)

    if type(document_id) is not int or document_id < 1:
        raise ValueError("Invalid document ID")

    if type(owner_user_id) is not int or owner_user_id < 1:
        raise ValueError("Invalid owner ID")

    filename = _get_owned_filename(
        db_path,
        document_id,
        owner_user_id
    )

    record = get_encrypted_key_record(
        document_id=document_id,
        owner_user_id=owner_user_id,
        db_path=db_path
    )

    if record is None:
        raise LookupError("Encrypted document not found")

    storage_id = record["storage_id"]
    validate_storage_id(storage_id)

    storage_dir = Path(storage_dir)

    if not storage_dir.is_dir() or storage_dir.is_symlink():
        raise ValueError("Trusted storage folder missing")

    storage_path = storage_dir / f"{storage_id}.svenc"

    if storage_path.is_symlink():
        raise ValueError("Unsafe encrypted file")

    data = storage_path.read_bytes()

    if len(data) < 29:
        raise ValueError("Invalid encrypted file")

    file_nonce = data[:12]
    encrypted_content = data[12:]

    # Recover the per-document encryption key.
    dek = AESGCM(kek).decrypt(
        record["wrap_nonce"],
        record["wrapped_dek"],
        _aad(
            "key",
            owner_user_id,
            document_id,
            storage_id,
            filename
        )
    )

    # AES-GCM detects modification to the encrypted
    # file or authenticated document context.
    plaintext = AESGCM(dek).decrypt(
        file_nonce,
        encrypted_content,
        _aad(
            "file",
            owner_user_id,
            document_id,
            storage_id,
            filename
        )
    )

    return plaintext
