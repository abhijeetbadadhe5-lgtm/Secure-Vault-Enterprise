
"""
Lesson 70: Encrypted upload deployment safety.

Checks filesystem location relationships before
using the existing Lesson 69 activation function.

Does not create keys, directories, or databases.
"""

from pathlib import Path

from fastapi import FastAPI

from backend.app.security.encrypted_upload_activation import (
    activate_encrypted_upload,
    ACTIVATION_SETTING
)

from backend.app.security.encrypted_upload_registration import (
    EncryptedUploadRegistrationError
)


PATH_SETTINGS = (
    "SECUREVAULT_UPLOAD_DB_PATH",
    "SECUREVAULT_UPLOAD_STORAGE_DIR",
    "SECUREVAULT_UPLOAD_KEK_DIR"
)


def _trusted_existing_path(value, *, is_directory):
    """
    Require an existing absolute filesystem path.

    Reject symlinks in the supplied path,
    including symlinked parent components.
    """

    if type(value) is not str or not value:
        raise ValueError("Invalid path setting")

    original = Path(value)

    if not original.is_absolute():
        raise ValueError("Path must be absolute")

    # Check every existing component before
    # resolving the complete path.
    for component in (original, *original.parents):
        if component.is_symlink():
            raise ValueError("Symbolic links not allowed")

    resolved = original.resolve(strict=True)

    if is_directory:
        if not resolved.is_dir():
            raise ValueError("Expected a directory")
    else:
        if not resolved.is_file():
            raise ValueError("Expected a file")

    return resolved


def validate_encrypted_upload_deployment(environment):
    """
    Validate deployment filesystem topology.

    Reject:
      - missing or relative locations
      - symlinked paths and parents
      - identical or nested storage/key folders
      - databases inside storage/key folders

    Existing Lesson 68 checks subsequently
    verify SQLite schema and DPAPI key recovery.
    """

    try:
        if environment is None:
            raise ValueError("Missing configuration")

        values = {}

        for setting in PATH_SETTINGS:
            value = environment.get(setting)

            if type(value) is not str or not value:
                raise ValueError("Missing path")

            values[setting] = value

        db_path = _trusted_existing_path(
            values["SECUREVAULT_UPLOAD_DB_PATH"],
            is_directory=False
        )

        storage_dir = _trusted_existing_path(
            values["SECUREVAULT_UPLOAD_STORAGE_DIR"],
            is_directory=True
        )

        key_directory = _trusted_existing_path(
            values["SECUREVAULT_UPLOAD_KEK_DIR"],
            is_directory=True
        )

        # Prevent using the same directory
        # or nesting one inside the other.
        if (
            storage_dir.is_relative_to(key_directory)
            or key_directory.is_relative_to(storage_dir)
        ):
            raise ValueError("Unsafe directory nesting")

        # Do not store the SQLite database inside
        # encrypted ciphertext or KEK directories.
        if (
            db_path.is_relative_to(storage_dir)
            or db_path.is_relative_to(key_directory)
        ):
            raise ValueError("Unsafe database location")

        return {
            "paths_safe": True,
            "db_path": db_path,
            "storage_dir": storage_dir,
            "key_directory": key_directory
        }

    except (OSError, ValueError, TypeError, AttributeError):
        raise EncryptedUploadRegistrationError(
            "Encrypted upload deployment paths are unsafe"
        ) from None


def activate_encrypted_upload_safely(app, environment):
    """
    Harden Lesson 69 activation.

    Disabled mode:
        Keep the upload endpoint disabled.

    Enabled mode:
        First validate filesystem topology.
        Then call the existing Lesson 69
        activation and Lesson 68 preflight.

    Do not suppress any failure.
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

    if enabled == "1":
        validate_encrypted_upload_deployment(
            environment
        )

    # Reuse all existing checks rather than
    # bypassing the Lesson 68/69 protections.
    return activate_encrypted_upload(
        app=app,
        environment=environment
    )
