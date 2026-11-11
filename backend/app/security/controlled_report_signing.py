
from backend.app.security.active_report_key import (
    ActiveReportKeyError,
    get_active_report_key_id
)

from backend.app.security.report_key_preflight import (
    check_report_signing_readiness
)

from backend.app.security.versioned_reporting import (
    create_versioned_report,
    verify_versioned_report
)


class ControlledReportSigningError(Exception):
    """The controlled report-signing workflow failed."""


def sign_report_safely(
    assessment,
    key_directory,
    environment=None
):
    """
    Create and verify an HMAC-authenticated report.

    1. Read the active key ID once.
    2. Check that the protected key is recoverable.
    3. Sign a sanitized report.
    4. Verify the resulting authentication tag.

    Does not create, replace, rotate or delete keys.
    Does not write to SQLite or save a report file.
    """

    # Step 1: Resolve the active key configuration.
    try:
        selected_key_id = get_active_report_key_id(
            environment
        )

    except ActiveReportKeyError:
        raise ControlledReportSigningError(
            "Controlled report signing failed"
        ) from None

    # Step 2: Run the existing Lesson 57 preflight.
    #
    # Use the ID already selected above. This ensures
    # we don't silently switch signing keys midway
    # because an environment setting changes.
    from backend.app.security.active_report_key import (
        ACTIVE_REPORT_KEY_ENV
    )

    selected_environment = {
        ACTIVE_REPORT_KEY_ENV: selected_key_id
    }

    try:
        preflight = check_report_signing_readiness(
            key_directory=key_directory,
            environment=selected_environment
        )

        if (
            preflight["ready"] is not True
            or preflight["status"] != "ready"
            or preflight["key_id"] != selected_key_id
            or preflight["key_recovery_verified"] is not True
        ):
            raise ValueError(
                "Signing preflight was not successful"
            )

        # Step 3: Use the selected existing protected
        # key to authenticate the sanitized report.
        envelope = create_versioned_report(
            assessment=assessment,
            key_directory=key_directory,
            key_id=selected_key_id
        )

        # Step 4: Verify the generated report.
        verified_report = verify_versioned_report(
            envelope=envelope,
            key_directory=key_directory
        )

        if (
            envelope["key_id"] != selected_key_id
            or envelope["report"] != verified_report
        ):
            raise ValueError(
                "Authenticated report verification mismatch"
            )

        return envelope

    except Exception:
        # No internal key, file or cryptographic
        # error details are returned to callers.
        raise ControlledReportSigningError(
            "Controlled report signing failed"
        ) from None
