
import re


# Conservative practice limit: 1 MiB.
# We will reconcile this with the existing
# FastAPI upload limit before integration.
MAX_PRACTICE_UPLOAD_BYTES = 1024 * 1024

# Example accepted names:
# report.txt
# quarterly_report_2026.txt
# notes-v2.TXT
SAFE_FILENAME = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]*\.txt",
    re.IGNORECASE
)

# Windows reserves these device names,
# including when followed by an extension.
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4",
    "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3",
    "LPT4", "LPT5", "LPT6", "LPT7",
    "LPT8", "LPT9"
}


class EncryptedUploadPreflightError(ValueError):
    """Incoming practice upload is not acceptable."""


def _validate_positive_id(value):
    """
    Require a positive integer.

    Reject booleans even though Python treats
    bool as a subclass of int.
    """
    return type(value) is int and value > 0


def _validate_filename(filename):
    """
    Accept only conservative, simple .txt names.

    Do not accept folder paths or special
    Windows device names.
    """

    if type(filename) is not str:
        raise EncryptedUploadPreflightError(
            "Invalid upload metadata"
        )

    if not 5 <= len(filename) <= 128:
        raise EncryptedUploadPreflightError(
            "Invalid upload metadata"
        )

    if SAFE_FILENAME.fullmatch(filename) is None:
        raise EncryptedUploadPreflightError(
            "Invalid upload metadata"
        )

    # Avoid ambiguous repeated dots.
    if ".." in filename:
        raise EncryptedUploadPreflightError(
            "Invalid upload metadata"
        )

    # The part before the first dot cannot be
    # a reserved Windows device name.
    basename = filename.split(".", 1)[0].upper()

    if basename in WINDOWS_RESERVED_NAMES:
        raise EncryptedUploadPreflightError(
            "Invalid upload metadata"
        )

    return filename


def prepare_encrypted_upload(
    filename,
    content,
    owner_user_id,
    document_id,
    max_bytes=MAX_PRACTICE_UPLOAD_BYTES
):
    """
    Validate input for a future encrypted upload.

    Does NOT:
      - save plaintext
      - create files
      - encrypt data
      - create or load keys
      - connect to SQLite
      - authenticate the owner

    Returns only a safe metadata summary.
    """

    try:
        if not _validate_positive_id(owner_user_id):
            raise ValueError("Invalid owner ID")

        if not _validate_positive_id(document_id):
            raise ValueError("Invalid document ID")

        if (
            type(max_bytes) is not int
            or not 1 <= max_bytes
                <= MAX_PRACTICE_UPLOAD_BYTES
        ):
            raise ValueError("Invalid size limit")

        safe_name = _validate_filename(filename)

        # Only immutable byte strings are accepted.
        # The API will need to bound reads before
        # constructing this in-memory value.
        if type(content) is not bytes:
            raise ValueError("Content must be bytes")

        content_size = len(content)

        if not 1 <= content_size <= max_bytes:
            raise ValueError("Invalid content size")

        # Intentionally do not return the content.
        return {
            "ready": True,
            "filename": safe_name,
            "size_bytes": content_size,
            "owner_user_id": owner_user_id,
            "document_id": document_id,
            "encryption_required": True,
            "plaintext_persisted": False
        }

    except (ValueError, TypeError):
        raise EncryptedUploadPreflightError(
            "Encrypted upload preflight failed"
        ) from None
