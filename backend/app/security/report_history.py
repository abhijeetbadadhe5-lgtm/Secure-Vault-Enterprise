
import json

from pathlib import Path

from backend.app.security.secure_report_file_verifier import (
    MAX_REPORT_BYTES,
    _reject_duplicate_keys,
    _reject_json_constant
)

from backend.app.security.versioned_reporting import (
    verify_versioned_report
)


MAX_HISTORY_FILES = 100


class ReportHistoryError(Exception):
    """Report history could not be scanned safely."""


def _verify_one_report_snapshot(
    report_path,
    key_directory
):
    """
    Read one bounded JSON file and verify its HMAC.

    Return the authenticated key ID.

    Read the file once, so the HMAC and key ID refer
    to the same in-memory snapshot.
    """

    if (
        report_path.is_symlink()
        or not report_path.is_file()
    ):
        raise ValueError("Invalid report file")

    with report_path.open("rb") as file:
        raw_data = file.read(
            MAX_REPORT_BYTES + 1
        )

    if len(raw_data) > MAX_REPORT_BYTES:
        raise ValueError("Report is too large")

    envelope = json.loads(
        raw_data.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_json_constant
    )

    # This validates the envelope, authenticates
    # the report and checks the recorded key ID.
    verify_versioned_report(
        envelope=envelope,
        key_directory=key_directory
    )

    # Only trust this field AFTER verification.
    return envelope["key_id"]


def scan_report_history(
    report_directory,
    key_directory
):
    """
    Scan existing JSON reports without modifying them.

    Returns:
      - total report count
      - verified report count
      - failed verification count
      - authenticated report counts by key version

    Never exposes individual filenames or plaintext.
    Never repairs, deletes or replaces anything.
    """

    directory = Path(report_directory)
    keys = Path(key_directory)

    if (
        directory.is_symlink()
        or not directory.is_dir()
        or keys.is_symlink()
        or not keys.is_dir()
    ):
        raise ReportHistoryError(
            "Report history scan unavailable"
        )

    try:
        # Scan only immediate JSON entries.
        # Subdirectories are not searched recursively.
        report_paths = sorted(
            (
                entry
                for entry in directory.iterdir()
                if entry.suffix == ".json"
            ),
            key=lambda entry: entry.name
        )

        # Fail closed if there are too many files.
        if len(report_paths) > MAX_HISTORY_FILES:
            raise ReportHistoryError(
                "Report history scan unavailable"
            )

    except OSError:
        raise ReportHistoryError(
            "Report history scan unavailable"
        ) from None

    verified_count = 0
    failed_count = 0
    key_version_counts = {}

    for path in report_paths:

        try:
            authenticated_key_id = (
                _verify_one_report_snapshot(
                    report_path=path,
                    key_directory=keys
                )
            )

        except Exception:
            # Do not trust metadata from a report
            # that fails authentication.
            failed_count += 1
            continue

        verified_count += 1

        key_version_counts[
            authenticated_key_id
        ] = (
            key_version_counts.get(
                authenticated_key_id,
                0
            ) + 1
        )

    # Sort for predictable administrative output.
    key_version_counts = dict(
        sorted(key_version_counts.items())
    )

    if failed_count:
        status = "review"
    elif verified_count:
        status = "verified"
    else:
        status = "empty"

    return {
        "status": status,
        "total_reports": len(report_paths),
        "verified_reports": verified_count,
        "failed_reports": failed_count,
        "key_version_counts": key_version_counts,
        "manual_review_required": failed_count > 0,
        "automatic_repairs_performed": False,
        "automatic_deletion_allowed": False
    }
