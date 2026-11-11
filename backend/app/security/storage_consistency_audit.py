
import re
import sqlite3

from contextlib import closing
from pathlib import Path


STORAGE_FILENAME_PATTERN = re.compile(
    r"[0-9a-f]{32}\.svenc"
)


def _require_existing_directory(directory):
    """
    Require a pre-existing, non-symlink folder.

    Never creates a directory.
    """
    path = Path(directory)

    if not path.is_dir() or path.is_symlink():
        raise ValueError(
            "Required trusted directory is unavailable"
        )

    return path


def audit_encrypted_storage(
    db_path,
    storage_dir,
    key_directory
):
    """
    Read-only consistency audit of practice storage.

    Checks:
      1. SQLite references with missing encrypted files
      2. Encrypted files with no SQLite reference
      3. Missing DPAPI-protected KEK files
      4. Suspicious or unexpected file paths

    Never deletes, repairs or rewrites data.
    """

    db_path = Path(db_path)

    if not db_path.is_file() or db_path.is_symlink():
        raise FileNotFoundError(
            "Existing SQLite database unavailable"
        )

    storage_dir = _require_existing_directory(
        storage_dir
    )

    key_directory = _require_existing_directory(
        key_directory
    )

    # Open SQLite in read-only mode.
    database_uri = db_path.resolve().as_uri() + "?mode=ro"

    with closing(
        sqlite3.connect(database_uri, uri=True)
    ) as connection:

        records = connection.execute(
            """
            SELECT
                document_id,
                storage_id,
                key_id
            FROM encrypted_document_keys
            ORDER BY document_id
            """
        ).fetchall()

    referenced_storage_ids = set()
    referenced_key_ids = set()

    missing_files = []
    missing_keys = []
    orphan_files = []
    unsafe_paths = []
    unexpected_files = []

    for document_id, storage_id, key_id in records:

        # Defense in depth: validate metadata
        # before creating paths from database values.
        if (
            type(storage_id) is not str
            or STORAGE_FILENAME_PATTERN.fullmatch(
                storage_id + ".svenc"
            ) is None
        ):
            unsafe_paths.append(
                f"invalid storage ID: document {document_id}"
            )
            continue

        referenced_storage_ids.add(storage_id)

        encrypted_path = (
            storage_dir / f"{storage_id}.svenc"
        )

        if encrypted_path.is_symlink():
            unsafe_paths.append(encrypted_path.name)

        elif not encrypted_path.is_file():
            missing_files.append(storage_id)

        # KEK IDs must not become arbitrary file paths.
        if (
            type(key_id) is not str
            or re.fullmatch(
                r"[A-Za-z0-9_-]{1,64}",
                key_id
            ) is None
        ):
            unsafe_paths.append(
                f"invalid key ID: document {document_id}"
            )
            continue

        referenced_key_ids.add(key_id)

    # Check each referenced protected key once.
    for key_id in sorted(referenced_key_ids):

        protected_path = (
            key_directory / f"{key_id}.dpapi"
        )

        if protected_path.is_symlink():
            unsafe_paths.append(protected_path.name)

        elif not protected_path.is_file():
            missing_keys.append(key_id)

    # Look for encrypted files that SQLite does
    # not reference.
    for entry in storage_dir.iterdir():

        if entry.suffix != ".svenc":
            continue

        if entry.is_symlink():
            if entry.name not in unsafe_paths:
                unsafe_paths.append(entry.name)
            continue

        if not STORAGE_FILENAME_PATTERN.fullmatch(
            entry.name
        ):
            unexpected_files.append(entry.name)
            continue

        if not entry.is_file():
            unexpected_files.append(entry.name)
            continue

        storage_id = entry.stem

        if storage_id not in referenced_storage_ids:
            orphan_files.append(storage_id)

    # Deterministic output helps automated tests.
    missing_files.sort()
    missing_keys.sort()
    orphan_files.sort()
    unsafe_paths.sort()
    unexpected_files.sort()

    consistent = not any(
        [
            missing_files,
            missing_keys,
            orphan_files,
            unsafe_paths,
            unexpected_files
        ]
    )

    return {
        "consistent": consistent,
        "record_count": len(records),
        "missing_files": missing_files,
        "orphan_files": orphan_files,
        "missing_keys": missing_keys,
        "unsafe_paths": unsafe_paths,
        "unexpected_files": unexpected_files
    }
