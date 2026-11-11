
"""
Lesson 69: Controlled encrypted-upload activation.

The real FastAPI application activates encrypted
uploads only when explicitly configured.

No database migrations, key creation or directory
creation happen here.
"""

from fastapi import FastAPI

from backend.app.security.encrypted_upload_registration import (
    EncryptedUploadRegistrationError,
    register_configured_encrypted_upload
)


ACTIVATION_SETTING = (
    "SECUREVAULT_ENABLE_ENCRYPTED_UPLOAD"
)


def activate_encrypted_upload(app, environment):
    """
    Activate encrypted uploads only when explicitly
    enabled by trusted backend configuration.

    Allowed setting values:

        absent or "0" -> disabled
        "1"           -> enable after preflight
        anything else -> reject configuration

    Missing or invalid required settings must
    prevent successful activation.
    """

    if not isinstance(app, FastAPI):
        raise EncryptedUploadRegistrationError(
            "A FastAPI application is required"
        )

    if environment is None:
        raise EncryptedUploadRegistrationError(
            "Trusted environment is required"
        )

    try:
        enabled = environment.get(
            ACTIVATION_SETTING,
            "0"
        )
    except (AttributeError, TypeError):
        raise EncryptedUploadRegistrationError(
            "Invalid activation environment"
        ) from None

    if enabled not in ("0", "1"):
        raise EncryptedUploadRegistrationError(
            "Invalid encrypted-upload activation setting"
        )

    if enabled == "0":
        return {
            "enabled": False,
            "registered": False
        }

    # The Lesson 68 registration function validates
    # all four required configuration settings,
    # the SQLite schema and the existing DPAPI KEK.
    #
    # If validation fails, its exception propagates.
    # The caller must not suppress that exception.

    result = register_configured_encrypted_upload(
        app=app,
        environment=environment
    )

    if result.get("registered") is not True:
        raise EncryptedUploadRegistrationError(
            "Encrypted-upload activation failed"
        )

    return {
        "enabled": True,
        "registered": True
    }
