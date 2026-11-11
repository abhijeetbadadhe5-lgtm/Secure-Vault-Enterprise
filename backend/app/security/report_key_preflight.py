
from backend.app.security.active_report_key import (
    ActiveReportKeyError,
    get_active_report_key_id
)

from backend.app.security.report_signing_key_store import (
    ReportSigningKeyError,
    _load_report_signing_key
)


def check_report_signing_readiness(
    key_directory,
    environment=None
):
    """
    Read-only preflight for the active HMAC signing key.

    Never creates, rotates, replaces or deletes keys.
    Never returns raw signing-key bytes.
    """

    # Step 1: Validate the active key configuration.
    try:
        key_id = get_active_report_key_id(
            environment
        )

    except ActiveReportKeyError:
        return {
            "ready": False,
            "status": "configuration_invalid",
            "reason": "Active report key configuration is invalid",
            "key_id": None,
            "key_recovery_verified": False
        }

    # Step 2: Attempt to recover the existing
    # DPAPI-protected signing key.
    try:
        signing_key = _load_report_signing_key(
            key_directory,
            key_id
        )

        # Defense in depth: check the recovered
        # key's type and length.
        if (
            type(signing_key) is not bytes
            or len(signing_key) != 32
        ):
            raise ValueError(
                "Invalid recovered signing key"
            )

    except (ReportSigningKeyError, ValueError):
        return {
            "ready": False,
            "status": "protected_key_unavailable",
            "reason": "Protected report signing key is unavailable",
            "key_id": key_id,
            "key_recovery_verified": False
        }

    # Step 3: Return only safe administrative metadata.
    # Never include the recovered signing key.
    return {
        "ready": True,
        "status": "ready",
        "reason": "Active report signing key is recoverable",
        "key_id": key_id,
        "key_recovery_verified": True
    }


def require_report_signing_ready(
    key_directory,
    environment=None
):
    """
    Require a successful preflight check before
    proceeding with an administrative workflow.

    Return the validated key ID.

    Does not create a new signing key.
    """

    result = check_report_signing_readiness(
        key_directory=key_directory,
        environment=environment
    )

    if not result["ready"]:
        raise ActiveReportKeyError(
            "Report signing is not ready"
        )

    return result["key_id"]
