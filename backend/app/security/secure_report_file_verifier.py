
import json

from pathlib import Path

from backend.app.security.versioned_reporting import (
    verify_versioned_report
)


# Maximum accepted JSON report size:
# 64 KiB = 65,536 bytes.
MAX_REPORT_BYTES = 64 * 1024


class SecureReportFileError(Exception):
    """Saved security report verification failed."""


def _reject_duplicate_keys(pairs):
    """
    Reject JSON objects containing duplicate keys.

    For example:
    {"status": "critical", "status": "healthy"}
    """
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")

        result[key] = value

    return result


def _reject_json_constant(value):
    """
    Reject non-standard JSON constants such as
    NaN, Infinity and -Infinity.
    """
    raise ValueError("Invalid JSON constant")


def verify_saved_report(
    report_path,
    key_directory
):
    """
    Read and authenticate an existing versioned
    SecureVault JSON report.

    Checks:
      1. The path is an existing regular file.
      2. The file is not a symbolic link.
      3. The size does not exceed 64 KiB.
      4. JSON is valid and unambiguous.
      5. The HMAC is valid under the recorded key ID.

    Does not create, edit or delete any file.
    """

    try:
        path = Path(report_path)

        # Reject a missing file, directory or
        # symbolic link.
        if path.is_symlink() or not path.is_file():
            raise ValueError("Invalid report path")

        # Read at most one byte over the limit.
        # This avoids loading arbitrarily large
        # files into Python memory.
        with path.open("rb") as file:
            raw_data = file.read(
                MAX_REPORT_BYTES + 1
            )

        if len(raw_data) > MAX_REPORT_BYTES:
            raise ValueError("Report too large")

        # Decode UTF-8 explicitly.
        text = raw_data.decode("utf-8")

        # JSON parsing may reject duplicate fields
        # and invalid numeric constants.
        envelope = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant
        )

        # Verify the versioned HMAC envelope using
        # its recorded DPAPI-protected signing key.
        verified_report = verify_versioned_report(
            envelope=envelope,
            key_directory=key_directory
        )

        return verified_report

    except Exception:
        # One generic error prevents callers from
        # relying on internal cryptographic details.
        raise SecureReportFileError(
            "Saved report verification failed"
        ) from None
