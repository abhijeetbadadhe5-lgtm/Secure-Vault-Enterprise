
import os
from pathlib import Path

import win32crypt

from backend.app.security.kek_config import (
    validate_kek_id
)

from backend.app.security.key_wrapping import (
    check_key
)


MAX_PROTECTED_FILE_BYTES = 4096


def get_key_store_directory(directory):
    """
    Check an existing, trusted key-storage directory.

    This function does not create missing directories.
    """

    directory = Path(directory)

    if directory.is_symlink():
        raise ValueError(
            "Key storage directory cannot be a symbolic link"
        )

    if not directory.is_dir():
        raise FileNotFoundError(
            "Key storage directory does not exist"
        )

    return directory.resolve(strict=True)


def get_protected_key_path(directory, key_id):
    """
    Build a local filename using a validated key ID.

    Never accept arbitrary filenames or directory paths.
    """

    validate_kek_id(key_id)

    root = get_key_store_directory(directory)

    return root / f"{key_id}.dpapi"


def save_protected_kek(directory, key_id, kek):
    """
    Protect and save one practice KEK using Windows DPAPI.

    Uses current-user DPAPI protection.
    Refuses to overwrite an existing key file.
    """

    validate_kek_id(key_id)
    check_key(kek, "KEK")

    file_path = get_protected_key_path(
        directory,
        key_id
    )

    # DPAPI encrypts the KEK using Windows protection.
    protected_bytes = win32crypt.CryptProtectData(
        kek,
        "SecureVault practice KEK",
        None,
        None,
        None,
        0
    )

    if len(protected_bytes) > MAX_PROTECTED_FILE_BYTES:
        raise ValueError(
            "Protected KEK exceeds expected size"
        )

    # Exclusive creation: no accidental overwrite.
    try:
        with open(file_path, "xb") as file:
            file.write(protected_bytes)
            file.flush()
            os.fsync(file.fileno())

    except FileExistsError:
        raise FileExistsError(
            "A protected KEK with this ID already exists"
        ) from None

    except BaseException:
        # The file has closed before cleanup.
        try:
            file_path.unlink()
        except OSError:
            pass
        raise

    return file_path


def load_protected_kek(directory, key_id):
    """
    Recover a KEK protected for the current Windows user.

    Never generates a replacement if recovery fails.
    """

    file_path = get_protected_key_path(
        directory,
        key_id
    )

    if file_path.is_symlink():
        raise ValueError(
            "Symbolic-link key files are not allowed"
        )

    with open(file_path, "rb") as file:
        protected_bytes = file.read(
            MAX_PROTECTED_FILE_BYTES + 1
        )

    if (
        not protected_bytes
        or len(protected_bytes) > MAX_PROTECTED_FILE_BYTES
    ):
        raise ValueError(
            "Invalid protected KEK file size"
        )

    # DPAPI returns a description and decrypted bytes.
    description, kek = win32crypt.CryptUnprotectData(
        protected_bytes,
        None,
        None,
        None,
        0
    )

    check_key(kek, "Recovered KEK")

    return {
        "key_id": key_id,
        "kek": kek
    }
