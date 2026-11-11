
import json
import secrets

from pathlib import Path

from backend.app.security.storage_consistency_audit import (
    audit_encrypted_storage
)

from backend.app.security.recovery_assessment import (
    assess_storage_report
)

from backend.app.security.controlled_report_signing import (
    sign_report_safely
)

from backend.app.security.secure_report_file_verifier import (
    MAX_REPORT_BYTES,
    verify_saved_report
)

from backend.app.security.report_history import (
    scan_report_history
)

from backend.app.security.report_retention import (
    assess_report_retention
)


class SecurityReportingPipelineError(Exception):
    """The security reporting pipeline failed."""


def publish_security_report(
    audit_report,
    key_directory,
    report_directory,
    environment,
    as_of=None,
    review_after_days=90
):
    """
    Assess, authenticate, save and verify one
    security report.

    Creates a NEW JSON report in an existing directory.
    Never overwrites an existing report.

    Does not modify SQLite, encrypted documents or
    protected signing keys.
    """

    try:
        report_directory = Path(report_directory)

        if (
            not report_directory.is_dir()
            or report_directory.is_symlink()
        ):
            raise ValueError(
                "Report directory unavailable"
            )

        # STEP 1:
        # Turn a Lesson 50 audit into a safe
        # Lesson 51 assessment.
        assessment = assess_storage_report(
            audit_report
        )

        # STEP 2:
        # Resolve the selected DPAPI signing key,
        # run preflight and authenticate the report.
        envelope = sign_report_safely(
            assessment=assessment,
            key_directory=key_directory,
            environment=environment
        )

        # STEP 3:
        # Check the authenticated report against
        # the Lesson 61 retention policy.
        retention = assess_report_retention(
            envelope=envelope,
            key_directory=key_directory,
            as_of=as_of,
            review_after_days=review_after_days
        )

        # STEP 4:
        # Serialize the authenticated envelope.
        json_text = json.dumps(
            envelope,
            sort_keys=True,
            indent=2,
            allow_nan=False
        ) + "\n"

        json_bytes = json_text.encode("utf-8")

        if len(json_bytes) > MAX_REPORT_BYTES:
            raise ValueError(
                "Authenticated report is too large"
            )

        # STEP 5:
        # Create a unique new file.
        # Mode 'x' refuses to overwrite an
        # existing report.
        report_name = (
            "verified-report-"
            + secrets.token_hex(16)
            + ".json"
        )

        report_path = (
            report_directory / report_name
        )

        with report_path.open(
            "x",
            encoding="utf-8"
        ) as output_file:
            output_file.write(json_text)

        # STEP 6:
        # Reopen the actual saved file and
        # verify its HMAC.
        verified = verify_saved_report(
            report_path=report_path,
            key_directory=key_directory
        )

        if verified != envelope["report"]:
            raise ValueError(
                "Saved report verification mismatch"
            )

        # STEP 7:
        # Scan existing reports and build the
        # verified key-version history.
        history = scan_report_history(
            report_directory=report_directory,
            key_directory=key_directory
        )

        return {
            "report_path": report_path,
            "status": verified["status"],
            "key_id": envelope["key_id"],
            "retention_decision": retention["decision"],
            "retention_manual_review": (
                retention["manual_review_required"]
            ),
            "history": history,
            "automatic_repairs_performed": False,
            "automatic_deletion_allowed": False
        }

    except Exception:
        raise SecurityReportingPipelineError(
            "Security reporting pipeline failed"
        ) from None



def audit_and_publish_security_report(
    db_path,
    storage_dir,
    document_key_directory,
    report_key_directory,
    report_directory,
    environment,
    as_of=None,
    review_after_days=90
):
    """
    Audit encrypted documents using their KEK directory.

    Sign the resulting report using a separate,
    existing DPAPI-protected HMAC signing key.

    Never writes to the document database.
    """

    try:
        audit_report = audit_encrypted_storage(
            db_path=db_path,
            storage_dir=storage_dir,
            key_directory=document_key_directory
        )

        return publish_security_report(
            audit_report=audit_report,
            key_directory=report_key_directory,
            report_directory=report_directory,
            environment=environment,
            as_of=as_of,
            review_after_days=review_after_days
        )

    except Exception:
        raise SecurityReportingPipelineError(
            "Security reporting pipeline failed"
        ) from None
