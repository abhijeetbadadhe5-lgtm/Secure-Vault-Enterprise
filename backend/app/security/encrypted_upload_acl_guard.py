
"""
Lesson 72: Windows ACL preflight for encrypted uploads.

Reads directory ACLs before enabling the
existing JWT-protected encrypted upload route.

Never changes ACLs, creates keys or writes
to the application database.
"""

from pathlib import Path

from fastapi import FastAPI

from backend.app.security.encrypted_upload_activation import (
    ACTIVATION_SETTING
)

from backend.app.security.encrypted_upload_registration import (
    EncryptedUploadRegistrationError
)

from backend.app.security.encrypted_upload_deployment_guard import (
    validate_encrypted_upload_deployment
)

from backend.app.security.encrypted_upload_identity_guard import (
    activate_encrypted_upload_with_identity
)


# Windows well-known groups that should not
# receive broad access to sensitive folders.
BROAD_PRINCIPALS = {
    "S-1-1-0",       # Everyone
    "S-1-5-11",      # Authenticated Users
    "S-1-5-32-545",  # BUILTIN\Users
    "S-1-5-32-546",  # BUILTIN\Guests
    "S-1-5-7"        # Anonymous Logon
}


# Windows access-mask bits.
GENERIC_ALL = 0x10000000
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000

# For a directory, these include creating
# files, creating subdirectories and changing
# its security or contents.
BROAD_WRITE_MASK = (
    GENERIC_ALL
    | GENERIC_WRITE
    | 0x00000002
    | 0x00000004
    | 0x00000010
    | 0x00000020
    | 0x00010000
    | 0x00040000
    | 0x00080000
)

# Directory read/list access.
BROAD_READ_MASK = (
    GENERIC_ALL
    | GENERIC_READ
    | 0x00000001
    | 0x00000008
    | 0x00000080
)


def inspect_directory_acl(directory):
    """
    Read the existing Windows DACL.

    Return a security summary without
    exposing individual account information.

    This is a conservative direct-ACE check,
    not a complete effective-access analysis.
    """

    import win32security

    path = Path(directory)

    if not path.is_dir():
        raise ValueError("ACL target is not a directory")

    security = win32security.GetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION
    )

    dacl = security.GetSecurityDescriptorDacl()

    # A NULL DACL can allow unrestricted access.
    # Reject it rather than treating it as safe.
    if dacl is None:
        return {
            "dacl_present": False,
            "broad_read": True,
            "broad_write": True
        }

    broad_read = False
    broad_write = False

    allowed_ace_types = {
        win32security.ACCESS_ALLOWED_ACE_TYPE,
        win32security.ACCESS_ALLOWED_OBJECT_ACE_TYPE
    }

    for index in range(dacl.GetAceCount()):
        ace = dacl.GetAce(index)

        ace_type = ace[0][0]

        if ace_type not in allowed_ace_types:
            continue

        access_mask = ace[1]
        trustee_sid = (
            win32security.ConvertSidToStringSid(
                ace[2]
            )
        )

        if trustee_sid not in BROAD_PRINCIPALS:
            continue

        if access_mask & BROAD_READ_MASK:
            broad_read = True

        if access_mask & BROAD_WRITE_MASK:
            broad_write = True

    return {
        "dacl_present": True,
        "broad_read": broad_read,
        "broad_write": broad_write
    }


def validate_encrypted_upload_acls(environment):
    """
    Require acceptable ACL summaries for:

      1. encrypted ciphertext storage
      2. the protected KEK directory

    Reuse Lesson 70 topology checks first.
    """

    try:
        paths = validate_encrypted_upload_deployment(
            environment
        )

        storage_acl = inspect_directory_acl(
            paths["storage_dir"]
        )

        key_acl = inspect_directory_acl(
            paths["key_directory"]
        )

        for result in (storage_acl, key_acl):
            if (
                type(result) is not dict
                or result.get("dacl_present") is not True
                or type(result.get("broad_read")) is not bool
                or type(result.get("broad_write")) is not bool
            ):
                raise ValueError(
                    "Invalid ACL inspection result"
                )

        if storage_acl["broad_write"]:
            raise ValueError(
                "Encrypted storage has broad write access"
            )

        if key_acl["broad_read"] or key_acl["broad_write"]:
            raise ValueError(
                "Protected key directory has broad access"
            )

        return {
            "acl_preflight_passed": True,
            "storage_checked": True,
            "key_directory_checked": True
        }

    except Exception:
        raise EncryptedUploadRegistrationError(
            "Encrypted upload ACL preflight failed"
        ) from None


def activate_encrypted_upload_with_acl(
    app,
    environment
):
    """
    Disabled:
        Leave the endpoint disabled.

    Enabled:
        Verify directory ACLs, then run the
        Lesson 71 identity guard and all
        previous deployment checks.
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

    if type(enabled) is not str or enabled not in (
        "0",
        "1"
    ):
        raise EncryptedUploadRegistrationError(
            "Invalid encrypted-upload activation setting"
        )

    if enabled == "1":
        validate_encrypted_upload_acls(
            environment
        )

    # Reuse:
    # Lesson 71 Windows identity verification
    # Lesson 70 deployment topology checks
    # Lesson 69 activation switch
    # Lesson 68 database/DPAPI preflight
    # Lesson 67 real JWT-protected router
    return activate_encrypted_upload_with_identity(
        app,
        environment
    )
