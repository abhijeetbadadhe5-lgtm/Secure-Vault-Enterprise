
import os

from collections.abc import Mapping

from backend.app.security.versioned_reporting import (
    _validate_key_id,
    create_versioned_report,
    verify_versioned_report
)


ACTIVE_REPORT_KEY_ENV = (
    "SECUREVAULT_ACTIVE_REPORT_KEY_ID"
)


class ActiveReportKeyError(Exception):
    """Active report signing key is unavailable."""


def get_active_report_key_id(environment=None):
    """
    Read and validate the selected signing-key ID.

    This function never creates or modifies a key.
    """

    if environment is None:
        environment = os.environ

    if not isinstance(environment, Mapping):
        raise ActiveReportKeyError(
            "Active report key configuration unavailable"
        )

    key_id = environment.get(
        ACTIVE_REPORT_KEY_ENV
    )

    try:
        _validate_key_id(key_id)

    except (ValueError, TypeError):
        raise ActiveReportKeyError(
            "Active report key configuration unavailable"
        ) from None

    return key_id


def create_report_with_active_key(
    assessment,
    key_directory,
    environment=None
):
    """
    Authenticate a new report using the selected key.

    The key must already exist in DPAPI storage.
    Never creates, replaces or deletes a key.
    """

    key_id = get_active_report_key_id(
        environment
    )

    try:
        envelope = create_versioned_report(
            assessment=assessment,
            key_directory=key_directory,
            key_id=key_id
        )

    except Exception:
        raise ActiveReportKeyError(
            "Active report signing failed"
        ) from None

    return envelope


def verify_report_with_original_key(
    envelope,
    key_directory
):
    """
    Verify an existing report using its recorded key ID.

    Does not consult the currently selected active key.
    """

    return verify_versioned_report(
        envelope=envelope,
        key_directory=key_directory
    )
