
import secrets

from pathlib import Path

from backend.app.security.kek_config import (
    validate_kek_id
)

from backend.app.security.windows_kek_store import (
    save_protected_kek,
    load_protected_kek
)

from backend.app.security.authenticated_reporting import (
    make_authenticated_report,
    verify_authenticated_report,
    ReportAuthenticationError
)


class ReportSigningKeyError(Exception):
    """A protected report-signing key operation failed."""


def _validate_report_key_id(key_id):
    """
    Use a dedicated namespace for report HMAC keys.

    Prevent accidental use of a document KEK identifier.
    """
    validate_kek_id(key_id)

    if not key_id.startswith("report-hmac-"):
        raise ValueError(
            "Report key ID must start with report-hmac-"
        )


def _validate_key_directory(key_directory):
    """
    Require an existing trusted key directory.

    Do not create, rename or replace a directory.
    """
    directory = Path(key_directory)

    if (
        not directory.is_dir()
        or directory.is_symlink()
    ):
        raise ValueError(
            "Protected report-key directory unavailable"
        )

    return directory


def provision_report_signing_key(
    key_directory,
    key_id
):
    """
    Generate one new random HMAC key and protect it
    using Windows DPAPI.

    Never overwrite an existing protected key.
    Never return the raw signing key.
    """
    _validate_report_key_id(key_id)
    directory = _validate_key_directory(
        key_directory
    )

    signing_key = secrets.token_bytes(32)

    try:
        save_protected_kek(
            directory,
            key_id,
            signing_key
        )

    except Exception:
        raise ReportSigningKeyError(
            "Report key provisioning failed"
        ) from None

    return key_id


def _load_report_signing_key(
    key_directory,
    key_id
):
    """
    Load an existing DPAPI-protected HMAC key.

    Never generate a replacement when recovery fails.
    """
    try:
        _validate_report_key_id(key_id)

        directory = _validate_key_directory(
            key_directory
        )

        loaded = load_protected_kek(
            directory,
            key_id
        )

        signing_key = loaded["kek"]

        if (
            type(signing_key) is not bytes
            or len(signing_key) != 32
        ):
            raise ValueError(
                "Invalid recovered signing key"
            )

        return signing_key

    except Exception:
        raise ReportSigningKeyError(
            "Protected report key unavailable"
        ) from None


def authenticate_report_with_dpapi(
    assessment,
    key_directory,
    key_id
):
    """
    Authenticate a sanitized recovery report using
    a previously provisioned protected signing key.
    """
    signing_key = _load_report_signing_key(
        key_directory,
        key_id
    )

    return make_authenticated_report(
        assessment,
        signing_key
    )


def verify_report_with_dpapi(
    authenticated_report,
    key_directory,
    key_id
):
    """
    Recover the existing signing key and verify
    an HMAC-authenticated report.

    Return the verified report on success.
    """
    signing_key = _load_report_signing_key(
        key_directory,
        key_id
    )

    return verify_authenticated_report(
        authenticated_report,
        signing_key
    )
