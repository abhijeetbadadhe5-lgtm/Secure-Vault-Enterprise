
import json
import uuid

from datetime import datetime, timezone
from pathlib import Path

from backend.app.security.recovery_assessment import (
    audit_and_assess_storage
)


# Trusted labels, severity levels and recommendations.
# These are NOT taken from filenames or user input.
REPORT_RULES = {
    "unsafe_paths": (
        "critical",
        "Review suspicious paths without opening "
        "or deleting files automatically."
    ),
    "missing_keys": (
        "critical",
        "Investigate protected KEK availability. "
        "Never generate a replacement KEK."
    ),
    "missing_files": (
        "critical",
        "Investigate missing encrypted files "
        "and verify available backups."
    ),
    "orphan_files": (
        "review",
        "Preserve unreferenced encrypted files "
        "for administrator investigation."
    ),
    "unexpected_files": (
        "review",
        "Review unexpected encrypted filenames. "
        "Do not rename or delete automatically."
    ),
}


def build_safe_recovery_report(assessment):
    """
    Turn a Lesson 51 assessment into a safe report.

    Only known fields are copied.
    Untrusted filenames, paths and identifiers
    are not included.
    """

    if not isinstance(assessment, dict):
        raise ValueError("Invalid recovery assessment")

    status = assessment.get("status")
    record_count = assessment.get("record_count")
    findings = assessment.get("findings")
    finding_count = assessment.get("finding_count")
    manual_review = assessment.get(
        "requires_manual_review"
    )

    if status not in ("healthy", "review", "critical"):
        raise ValueError("Invalid recovery status")

    if (
        type(record_count) is not int
        or record_count < 0
    ):
        raise ValueError("Invalid record count")

    if (
        type(finding_count) is not int
        or finding_count < 0
    ):
        raise ValueError("Invalid finding count")

    if type(manual_review) is not bool:
        raise ValueError("Invalid review flag")

    if not isinstance(findings, list):
        raise ValueError("Invalid findings")

    if assessment.get(
        "automatic_repairs_performed"
    ) is not False:
        raise ValueError("Unexpected repair state")

    if assessment.get(
        "safe_to_auto_delete"
    ) is not False:
        raise ValueError("Unsafe deletion state")

    safe_findings = []
    seen_types = set()

    for item in findings:

        if not isinstance(item, dict):
            raise ValueError("Invalid finding")

        finding_type = item.get("type")
        count = item.get("count")

        if finding_type not in REPORT_RULES:
            raise ValueError("Unknown finding type")

        if finding_type in seen_types:
            raise ValueError("Duplicate finding type")

        if type(count) is not int or count < 1:
            raise ValueError("Invalid finding count")

        expected_severity, action = (
            REPORT_RULES[finding_type]
        )

        if item.get("severity") != expected_severity:
            raise ValueError("Invalid finding severity")

        seen_types.add(finding_type)

        safe_findings.append({
            "category": finding_type,
            "severity": expected_severity,
            "count": count,
            "recommended_action": action
        })

    safe_findings.sort(
        key=lambda item: item["category"]
    )

    if sum(
        item["count"] for item in safe_findings
    ) != finding_count:
        raise ValueError("Finding counts do not match")

    if any(
        item["severity"] == "critical"
        for item in safe_findings
    ):
        expected_status = "critical"
    elif safe_findings:
        expected_status = "review"
    else:
        expected_status = "healthy"

    if status != expected_status:
        raise ValueError("Recovery status mismatch")

    if manual_review != bool(safe_findings):
        raise ValueError("Manual review flag mismatch")

    return {
        "report_version": 1,
        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(timespec="seconds"),
        "status": status,
        "document_reference_count": record_count,
        "total_findings": finding_count,
        "requires_manual_review": manual_review,
        "automatic_repairs_performed": False,
        "automatic_deletion_allowed": False,
        "findings": safe_findings
    }


def save_safe_recovery_report(
    assessment,
    report_directory
):
    """
    Create a NEW JSON report without overwriting
    an existing file.

    Never saves raw keys, filenames, storage IDs
    or plaintext document contents.
    """

    safe_report = build_safe_recovery_report(
        assessment
    )

    directory = Path(report_directory)

    if (
        not directory.is_dir()
        or directory.is_symlink()
    ):
        raise ValueError(
            "Trusted report directory is unavailable"
        )

    # A random filename prevents predictable
    # report names. 'x' refuses to overwrite.
    report_name = (
        f"recovery-report-{uuid.uuid4().hex}.json"
    )

    report_path = directory / report_name

    with report_path.open(
        "x",
        encoding="utf-8"
    ) as output_file:

        json.dump(
            safe_report,
            output_file,
            indent=2,
            sort_keys=True
        )

        output_file.write("\n")

    return report_path


def audit_assess_and_save_report(
    db_path,
    storage_dir,
    key_directory,
    report_directory
):
    """
    Run a read-only audit and assessment,
    then save only a sanitized summary.

    Does not modify encrypted storage,
    SQLite records or protected keys.
    """

    assessment = audit_and_assess_storage(
        db_path=db_path,
        storage_dir=storage_dir,
        key_directory=key_directory
    )

    return save_safe_recovery_report(
        assessment=assessment,
        report_directory=report_directory
    )
