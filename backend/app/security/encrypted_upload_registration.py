
import re
import sqlite3

from contextlib import closing
from pathlib import Path

from fastapi import FastAPI
from starlette.routing import NoMatchFound

from backend.app.security.windows_kek_store import (
    load_protected_kek
)

from backend.app.security.jwt_encrypted_upload_integration import (
    create_jwt_encrypted_upload_router
)


REQUIRED_SETTINGS = (
    "SECUREVAULT_UPLOAD_DB_PATH",
    "SECUREVAULT_UPLOAD_STORAGE_DIR",
    "SECUREVAULT_UPLOAD_KEK_DIR",
    "SECUREVAULT_UPLOAD_KEK_ID"
)

UPLOAD_ROUTE_NAME = "upload_encrypted_document"


class EncryptedUploadRegistrationError(Exception):
    """Encrypted upload configuration is not ready."""


def _existing_path(value, directory):
    """
    Require an absolute existing path.

    No folders or files are created.
    """
    if type(value) is not str or not value:
        raise ValueError("Missing path")

    path = Path(value)

    if not path.is_absolute():
        raise ValueError("Path must be absolute")

    if path.is_symlink():
        raise ValueError("Symbolic link rejected")

    if directory:
        if not path.is_dir():
            raise ValueError("Directory unavailable")
    else:
        if not path.is_file():
            raise ValueError("File unavailable")

    return path


def check_encrypted_upload_configuration(environment):
    """
    Verify explicitly supplied backend configuration.

    This function never:
      - creates a database
      - migrates SQLite
      - saves ciphertext
      - creates or replaces KEKs
      - registers HTTP routes

    The environment argument must be a mapping
    of trusted configuration values.
    """

    try:
        if environment is None:
            raise ValueError("Configuration required")

        values = {}

        for name in REQUIRED_SETTINGS:
            value = environment.get(name)

            if type(value) is not str or not value:
                raise ValueError("Missing setting")

            values[name] = value

        db_path = _existing_path(
            values["SECUREVAULT_UPLOAD_DB_PATH"],
            directory=False
        )

        storage_dir = _existing_path(
            values["SECUREVAULT_UPLOAD_STORAGE_DIR"],
            directory=True
        )

        key_directory = _existing_path(
            values["SECUREVAULT_UPLOAD_KEK_DIR"],
            directory=True
        )

        key_id = values["SECUREVAULT_UPLOAD_KEK_ID"]

        if re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}",
            key_id
        ) is None:
            raise ValueError("Invalid key identifier")

        # The encrypted storage and protected-key
        # directories must not be the same place.
        if storage_dir.resolve() == key_directory.resolve():
            raise ValueError("Directories overlap")

        # Inspect the existing SQLite schema
        # using a read-only connection.
        db_uri = db_path.resolve().as_uri() + "?mode=ro"

        with closing(
            sqlite3.connect(db_uri, uri=True)
        ) as connection:

            required_tables = {
                "owned_documents",
                "encrypted_document_keys"
            }

            found_tables = {
                row[0]
                for row in connection.execute(
                    """
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'table'
                    """
                )
            }

            if not required_tables.issubset(found_tables):
                raise ValueError("Database schema missing")

        # Confirm the existing DPAPI-protected KEK
        # can be recovered by this Windows account.
        recovered = load_protected_kek(
            key_directory,
            key_id
        )

        if (
            type(recovered) is not dict
            or type(recovered.get("kek")) is not bytes
            or len(recovered["kek"]) != 32
        ):
            raise ValueError("Protected KEK unavailable")

        # Do not return the actual KEK bytes.
        return {
            "ready": True,
            "db_path": db_path,
            "storage_dir": storage_dir,
            "key_directory": key_directory,
            "key_id": key_id,
            "key_recovery_verified": True
        }

    except Exception:
        raise EncryptedUploadRegistrationError(
            "Encrypted upload configuration unavailable"
        ) from None


def register_configured_encrypted_upload(
    app,
    environment
):
    """
    Register the existing real-JWT upload router
    on a supplied FastAPI application.

    Reject duplicate registration.
    """

    if not isinstance(app, FastAPI):
        raise EncryptedUploadRegistrationError(
            "A FastAPI application is required"
        )

    if getattr(
        app.state,
        "securevault_encrypted_upload_registered",
        False
    ):
        raise EncryptedUploadRegistrationError(
            "Encrypted upload already registered"
        )

    # Detect a pre-existing endpoint with the
    # same route name where FastAPI exposes it.
    try:
        app.url_path_for(
            UPLOAD_ROUTE_NAME,
            document_id=1
        )
    except NoMatchFound:
        pass
    else:
        raise EncryptedUploadRegistrationError(
            "Encrypted upload already registered"
        )

    config = check_encrypted_upload_configuration(
        environment
    )

    router = create_jwt_encrypted_upload_router(
        db_path=config["db_path"],
        storage_dir=config["storage_dir"],
        key_directory=config["key_directory"],
        key_id=config["key_id"]
    )

    app.include_router(router)

    app.state.securevault_encrypted_upload_registered = True

    return {
        "registered": True,
        "configuration_ready": True,
        "jwt_dependency_required": True
    }
