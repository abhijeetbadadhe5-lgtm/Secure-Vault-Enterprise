
import hashlib
import re


# Maximum file size: 1 MiB
MAX_UPLOAD_BYTES = 1024 * 1024

# Only plain-text practice files are accepted.
ALLOWED_EXTENSION = ".txt"

# Windows reserves these names for devices.
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5",
    "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
    "LPT6", "LPT7", "LPT8", "LPT9"
}


def validate_upload(filename, content):
    """
    Validate a small UTF-8 text upload.

    Returns safe metadata only.
    Does not write the file to disk.
    """

    # STEP 1: Check filename type.
    if not isinstance(filename, str):
        raise ValueError("Filename must be text")

    if not filename or len(filename) > 100:
        raise ValueError(
            "Filename must contain 1 to 100 characters"
        )

    # STEP 2: Reject paths and unusual filenames.
    if "/" in filename or "\\" in filename:
        raise ValueError("Directory paths are not allowed")

    if ".." in filename:
        raise ValueError("Double dots are not allowed")

    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]*\.txt",
        filename
    ):
        raise ValueError(
            "Only simple .txt filenames are allowed"
        )

    base_name = filename.rsplit(".", 1)[0].upper()

    if base_name in WINDOWS_RESERVED_NAMES:
        raise ValueError("Reserved filename is not allowed")

    # STEP 3: Require actual byte content.
    if not isinstance(content, bytes):
        raise ValueError("Content must be bytes")

    if len(content) == 0:
        raise ValueError("Empty files are not allowed")

    # STEP 4: Apply the file size limit.
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError("File exceeds the 1 MiB limit")

    # STEP 5: Verify UTF-8 text.
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(
            "File must contain valid UTF-8 text"
        ) from None

    # STEP 6: Reject NUL bytes.
    if b"\x00" in content:
        raise ValueError(
            "NUL characters are not allowed"
        )

    # STEP 7: Calculate metadata.
    file_hash = hashlib.sha256(content).hexdigest()

    return {
        "filename": filename,
        "size_bytes": len(content),
        "sha256": file_hash
    }
