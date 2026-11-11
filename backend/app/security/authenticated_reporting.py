
import hashlib
import hmac
import json
import re
import uuid

from pathlib import Path

from backend.app.security.recovery_reporting import (
    build_safe_recovery_report
)


class ReportAuthenticationError(Exception):
    """A report could not be authenticated."""


def _validate_signing_key(signing_key):
    """Use a separate, 32-byte HMAC signing key."""

    if type(signing_key) is not bytes:
        raise ValueError(
            "Report signing key must be bytes"
        )

    if len(signing_key) != 32:
        raise ValueError(
            "Report signing key must be 32 bytes"
        )


def _canonical_bytes(report):
    """
    Convert a report into predictable JSON bytes.

    The same JSON values must produce the same
    byte representation for HMAC verification.
    """

    return json.dumps(
        report,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False
    ).encode("utf-8")


def make_authenticated_report(
    assessment,
    signing_key
):
    """
    Build a sanitized Lesson 52 report and
    authenticate it using HMAC-SHA256.
    """

    _validate_signing_key(signing_key)

    safe_report = build_safe_recovery_report(
        assessment
    )

    tag = hmac.new(
        signing_key,
        _canonical_bytes(safe_report),
        hashlib.sha256
    ).hexdigest()

    return {
        "envelope_version": 1,
        "algorithm": "HMAC-SHA256",
        "report": safe_report,
        "authentication_tag": tag
    }


def verify_authenticated_report(
    authenticated_report,
    signing_key
):
    """
    Verify a report using the trusted signing key.

    Raise a generic error if validation fails.
    Return the authenticated report on success.
    """

    _validate_signing_key(signing_key)

    try:
        envelope = authenticated_report

        if not isinstance(envelope, dict):
            raise ValueError("Invalid envelope")

        if set(envelope) != {
            "envelope_version",
            "algorithm",
            "report",
            "authentication_tag"
        }:
            raise ValueError("Unexpected fields")

        if type(envelope["envelope_version"]) is not int:
            raise ValueError("Invalid version")

        if envelope["envelope_version"] != 1:
            raise ValueError("Unsupported version")

        if envelope["algorithm"] != "HMAC-SHA256":
            raise ValueError("Unsupported algorithm")

        report = envelope["report"]
        tag = envelope["authentication_tag"]

        if not isinstance(report, dict):
            raise ValueError("Invalid report")

        if (
            type(tag) is not str
            or re.fullmatch(r"[0-9a-f]{64}", tag)
            is None
        ):
            raise ValueError("Invalid tag")

        expected_tag = hmac.new(
            signing_key,
            _canonical_bytes(report),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(
            tag,
            expected_tag
        ):
            raise ValueError("Tag mismatch")

        return report

    except (
        ValueError,
        TypeError,
        KeyError,
        OverflowError
    ):
        raise ReportAuthenticationError(
            "Report authentication failed"
        ) from None


def save_authenticated_report(
    assessment,
    signing_key,
    report_directory
):
    """
    Save a new authenticated report.

    Existing reports are never overwritten.
    """

    envelope = make_authenticated_report(
        assessment,
        signing_key
    )

    directory = Path(report_directory)

    if (
        not directory.is_dir()
        or directory.is_symlink()
    ):
        raise ValueError(
            "Trusted report directory unavailable"
        )

    filename = (
        "authenticated-report-"
        + uuid.uuid4().hex
        + ".json"
    )

    report_path = directory / filename

    # Mode 'x' refuses to overwrite a file.
    with report_path.open(
        "x",
        encoding="utf-8"
    ) as file:
        json.dump(
            envelope,
            file,
            sort_keys=True,
            indent=2
        )

        file.write("\n")

    return report_path


def _reject_duplicate_json_keys(pairs):
    """
    Reject ambiguous JSON containing duplicate keys.
    """

    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(
                "Duplicate JSON field"
            )

        result[key] = value

    return result


def verify_authenticated_report_file(
    report_path,
    signing_key
):
    """
    Read and authenticate a saved JSON report.

    Does not modify the file.
    """

    _validate_signing_key(signing_key)

    path = Path(report_path)

    if path.is_symlink() or not path.is_file():
        raise ReportAuthenticationError(
            "Report authentication failed"
        )

    try:
        # Bound report size: do not read unbounded data.
        with path.open("rb") as file:
            data = file.read(65537)

        if len(data) > 65536:
            raise ValueError("Report is too large")

        envelope = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys
        )

    except (
        OSError,
        UnicodeError,
        ValueError,
        TypeError
    ):
        raise ReportAuthenticationError(
            "Report authentication failed"
        ) from None

    return verify_authenticated_report(
        envelope,
        signing_key
    )
