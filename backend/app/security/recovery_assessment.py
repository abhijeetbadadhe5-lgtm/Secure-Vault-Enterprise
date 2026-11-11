
from backend.app.security.storage_consistency_audit import (
    audit_encrypted_storage
)


# Each finding has a priority and a safe recommendation.
# No recommendation performs automatic changes.

FINDING_RULES = (
    (
        "unsafe_paths",
        "critical",
        "Review suspicious paths and restrict access. "
        "Do not open or delete unknown files automatically."
    ),
    (
        "missing_keys",
        "critical",
        "Investigate protected KEK availability. "
        "Do not generate a replacement KEK."
    ),
    (
        "missing_files",
        "critical",
        "Investigate missing encrypted files and check "
        "verified backups. Do not overwrite metadata."
    ),
    (
        "orphan_files",
        "review",
        "Preserve unreferenced encrypted files and "
        "investigate their origin before taking action."
    ),
    (
        "unexpected_files",
        "review",
        "Review unexpected encrypted filenames. "
        "Do not automatically rename or delete them."
    ),
)


def assess_storage_report(audit_report):
    """
    Convert a Lesson 50 audit report into a
    safe, non-destructive recovery assessment.

    This function does not access the filesystem
    or modify SQLite.
    """

    if not isinstance(audit_report, dict):
        raise ValueError("Invalid storage audit report")

    required_fields = {
        "consistent",
        "record_count",
        "missing_files",
        "orphan_files",
        "missing_keys",
        "unsafe_paths",
        "unexpected_files"
    }

    if not required_fields.issubset(audit_report):
        raise ValueError("Incomplete storage audit report")

    if type(audit_report["consistent"]) is not bool:
        raise ValueError("Invalid consistency flag")

    record_count = audit_report["record_count"]

    if type(record_count) is not int or record_count < 0:
        raise ValueError("Invalid record count")

    # Validate all finding lists before interpreting them.
    for field, _, _ in FINDING_RULES:
        values = audit_report[field]

        if (
            not isinstance(values, list)
            or any(
                type(item) is not str or not item
                for item in values
            )
        ):
            raise ValueError(
                "Invalid audit findings"
            )

    has_findings = any(
        audit_report[field]
        for field, _, _ in FINDING_RULES
    )

    if audit_report["consistent"] == has_findings:
        raise ValueError(
            "Inconsistent audit report"
        )

    findings = []
    has_critical = False

    for field, severity, recommendation in FINDING_RULES:

        count = len(audit_report[field])

        if count == 0:
            continue

        findings.append(
            {
                "type": field,
                "severity": severity,
                "count": count,
                "recommendation": recommendation
            }
        )

        if severity == "critical":
            has_critical = True

    if has_critical:
        status = "critical"
    elif findings:
        status = "review"
    else:
        status = "healthy"

    return {
        "status": status,
        "record_count": record_count,
        "finding_count": sum(
            item["count"]
            for item in findings
        ),
        "findings": findings,
        "requires_manual_review": bool(findings),
        "automatic_repairs_performed": False,
        "safe_to_auto_delete": False
    }


def audit_and_assess_storage(
    db_path,
    storage_dir,
    key_directory
):
    """
    Run the existing read-only auditor and
    assess its findings.

    Never performs repairs or deletes files.
    """

    report = audit_encrypted_storage(
        db_path=db_path,
        storage_dir=storage_dir,
        key_directory=key_directory
    )

    return assess_storage_report(report)
