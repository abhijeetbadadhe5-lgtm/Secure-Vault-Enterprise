
import hashlib
import hmac
import json
import re

from backend.app.security.recovery_reporting import (
    build_safe_recovery_report
)

from backend.app.security.report_signing_key_store import (
    provision_report_signing_key,
    _load_report_signing_key
)


REPORT_FORMAT_VERSION = 1
REPORT_DOMAIN = b"SecureVault-versioned-report-v1\x00"

KEY_ID_PATTERN = re.compile(
    r"report-hmac-[A-Za-z0-9_-]{1,52}"
)


class VersionedReportError(Exception):
    """Versioned report verification failed."""


def _validate_key_id(key_id):
    """
    Accept only safe report-signing key IDs.

    Never use arbitrary text as a key filename.
    """
    if (
        type(key_id) is not str
        or KEY_ID_PATTERN.fullmatch(key_id) is None
    ):
        raise ValueError("Invalid report key ID")


def _authenticated_bytes(key_id, report):
    """
    Authenticate the report AND its key ID.

    A domain separator prevents this HMAC format
    from being confused with another application.
    """
    payload = {
        "format_version": REPORT_FORMAT_VERSION,
        "key_id": key_id,
        "report": report
    }

    canonical_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False
    ).encode("utf-8")

    return REPORT_DOMAIN + canonical_json


def provision_new_report_key(
    key_directory,
    new_key_id
):
    """
    Create an independent, protected signing key.

    Existing protected keys are never overwritten.
    """
    _validate_key_id(new_key_id)

    return provision_report_signing_key(
        key_directory,
        new_key_id
    )


def create_versioned_report(
    assessment,
    key_directory,
    key_id
):
    """
    Build and authenticate a sanitized report.

    The report records which protected key was used.
    """
    _validate_key_id(key_id)

    signing_key = _load_report_signing_key(
        key_directory,
        key_id
    )

    safe_report = build_safe_recovery_report(
        assessment
    )

    tag = hmac.new(
        signing_key,
        _authenticated_bytes(
            key_id,
            safe_report
        ),
        hashlib.sha256
    ).hexdigest()

    return {
        "format_version": REPORT_FORMAT_VERSION,
        "key_id": key_id,
        "report": safe_report,
        "authentication_tag": tag
    }


def verify_versioned_report(
    envelope,
    key_directory
):
    """
    Verify a report using its recorded key ID.

    Never generates a missing replacement key.
    Never changes the report or key files.
    """
    try:
        if type(envelope) is not dict:
            raise ValueError("Invalid envelope")

        expected_fields = {
            "format_version",
            "key_id",
            "report",
            "authentication_tag"
        }

        if set(envelope) != expected_fields:
            raise ValueError("Unexpected fields")

        if (
            type(envelope["format_version"]) is not int
            or envelope["format_version"]
                != REPORT_FORMAT_VERSION
        ):
            raise ValueError("Unsupported format")

        key_id = envelope["key_id"]
        _validate_key_id(key_id)

        report = envelope["report"]
        tag = envelope["authentication_tag"]

        if type(report) is not dict:
            raise ValueError("Invalid report")

        if (
            type(tag) is not str
            or re.fullmatch(r"[0-9a-f]{64}", tag)
                is None
        ):
            raise ValueError("Invalid authentication tag")

        signing_key = _load_report_signing_key(
            key_directory,
            key_id
        )

        expected_tag = hmac.new(
            signing_key,
            _authenticated_bytes(
                key_id,
                report
            ),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(
            tag,
            expected_tag
        ):
            raise ValueError("Authentication failed")

        return report

    except Exception:
        raise VersionedReportError(
            "Versioned report authentication failed"
        ) from None
