
import os
import re
import secrets

from pathlib import Path

from backend.app.security.upload_validation import (
    MAX_UPLOAD_BYTES
)


# Magic bytes identify our practice storage format.
FILE_HEADER = b"SV01"

# AES-GCM standard nonce size.
NONCE_SIZE = 12

# AES-GCM authentication tag size.
TAG_SIZE = 16

# Each stored document gets a random 32-character ID.
STORAGE_ID_PATTERN = re.compile(r"[0-9a-f]{32}")

# Maximum supported encrypted blob size.
MAX_STORED_BYTES = (
    len(FILE_HEADER)
    + NONCE_SIZE
    + MAX_UPLOAD_BYTES
    + TAG_SIZE
)


def validate_storage_id(storage_id):
    """Accept only our 32-character hexadecimal IDs."""

    if not isinstance(storage_id, str):
        raise ValueError("Storage ID must be text")

    if STORAGE_ID_PATTERN.fullmatch(storage_id) is None:
        raise ValueError("Invalid storage ID")

    return storage_id


def get_storage_root(storage_root):
    """
    Resolve an existing, trusted storage directory.

    This function never creates a missing directory.
    """

    root = Path(storage_root)

    if root.is_symlink():
        raise ValueError(
            "Storage directory cannot be a symbolic link"
        )

    if not root.is_dir():
        raise FileNotFoundError(
            "Storage directory does not exist"
        )

    return root.resolve(strict=True)


def get_encrypted_path(storage_root, storage_id):
    """
    Generate a path from a validated storage ID only.

    Never use an uploaded filename here.
    """

    validate_storage_id(storage_id)

    root = get_storage_root(storage_root)

    return root / f"{storage_id}.svenc"




def save_encrypted_document(
    storage_root,
    nonce,
    ciphertext
):
    """
    Save an encrypted blob under a random ID.

    Never stores or accepts the secret encryption key.
    """

    if not isinstance(nonce, bytes):
        raise ValueError("Nonce must be bytes")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce must be 12 bytes")

    if not isinstance(ciphertext, bytes):
        raise ValueError("Ciphertext must be bytes")

    if not TAG_SIZE <= len(ciphertext) <= (
        MAX_UPLOAD_BYTES + TAG_SIZE
    ):
        raise ValueError("Invalid ciphertext size")

    root = get_storage_root(storage_root)

    blob = FILE_HEADER + nonce + ciphertext

    for _ in range(10):
        storage_id = secrets.token_hex(16)
        file_path = root / f"{storage_id}.svenc"

        try:
            # Refuse to replace any existing file.
            with open(file_path, "xb") as file:
                try:
                    file.write(blob)
                    file.flush()
                    os.fsync(file.fileno())

                except BaseException:
                    # File is closed before cleanup below.
                    raise

        except FileExistsError:
            # Generate another random ID.
            continue

        except BaseException:
            # Cleanup happens after the with-block
            # has closed the file on Windows.
            try:
                file_path.unlink()
            except OSError:
                pass

            raise

        return storage_id

    raise RuntimeError(
        "Could not allocate a unique storage ID"
    )

def load_encrypted_document(storage_root, storage_id):
    """
    Read a stored encrypted blob.

    Returns the nonce and ciphertext.
    It does not decrypt the content.
    """

    file_path = get_encrypted_path(
        storage_root,
        storage_id
    )

    # Reject an existing symbolic-link file.
    if file_path.is_symlink():
        raise ValueError(
            "Symbolic-link storage files are not allowed"
        )

    # Read one byte beyond our maximum for size checking.
    with open(file_path, "rb") as file:
        blob = file.read(MAX_STORED_BYTES + 1)

    if len(blob) > MAX_STORED_BYTES:
        raise ValueError("Stored file exceeds size limit")

    if len(blob) < (
        len(FILE_HEADER) + NONCE_SIZE + TAG_SIZE
    ):
        raise ValueError("Stored encrypted data is incomplete")

    if not blob.startswith(FILE_HEADER):
        raise ValueError("Unrecognized encrypted file format")

    nonce_start = len(FILE_HEADER)
    nonce_end = nonce_start + NONCE_SIZE

    nonce = blob[nonce_start:nonce_end]
    ciphertext = blob[nonce_end:]

    return {
        "nonce": nonce,
        "ciphertext": ciphertext
    }
