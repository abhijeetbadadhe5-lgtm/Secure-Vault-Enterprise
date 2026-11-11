
"""
Lesson 73: Individual DPAPI key-file ACL security.

Inspect the existing protected KEK file before
allowing encrypted-upload activation.

No ACL changes, key creation, or database writes.
"""

from pathlib import Path

from fastapi import FastAPI

from backend.app.security.encrypted_upload_activation import (
    ACTIVATION_SETTING
)

from backend.app.security.encrypted_upload_acl_guard import (
    BROAD_PRINCIPALS,
    BROAD_READ_MASK,
    BROAD_WRITE_MASK,
    activate_encrypted_upload_with_acl
)

from backend.app.security.encrypted_upload_deployment_guard import (
    validate_encrypted_upload_deployment
)

from backend.app.security.encrypted_upload_registration import (
    EncryptedUploadRegistrationError
)

from backend.app.security.windows_kek_store import (
    get_protected_key_path
)


# Windows ACE flag indicating that the
# permission entry was inherited.
INHERITED_ACE_FLAG = 0x10


def inspect_protected_key_file_acl(file_path):
    """
    Read the Windows DACL of one existing file.

    Inspect standard allow ACEs for selected
    broad Windows groups.

    Reject unsupported ACE types rather than
    incorrectly treating them as safe.

    Return only security status information,
    never the protected key's contents.
    """

    import win32security

    path = Path(file_path)

    if not path.is_file() or path.is_symlink():
        raise ValueError("Protected key file unavailable")

    security = win32security.GetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION
    )

    dacl = security.GetSecurityDescriptorDacl()

    if dacl is None:
        return {
            "dacl_present": False,
            "broad_read": True,
            "broad_write": True,
            "inherited_ace_count": 0
        }

    broad_read = False
    broad_write = False
    inherited_count = 0

    for index in range(dacl.GetAceCount()):
        ace = dacl.GetAce(index)

        ace_type = ace[0][0]
        ace_flags = ace[0][1]

        if ace_flags & INHERITED_ACE_FLAG:
            inherited_count += 1

        # Standard access-denied ACEs do not
        # grant access. For this conservative
        # preflight, they can be skipped.
        if ace_type == (
            win32security.ACCESS_DENIED_ACE_TYPE
        ):
            continue

        # Other ACE formats can have different
        # structures. Reject unknown formats
        # rather than accidentally misreading
        # their security meaning.
        if ace_type != (
            win32security.ACCESS_ALLOWED_ACE_TYPE
        ):
            raise ValueError(
                "Unsupported key-file ACE type"
            )

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
        "broad_write": broad_write,
        "inherited_ace_count": inherited_count
    }


def validate_protected_key_file_acl(environment):
    """
    Check the actual protected KEK file.

    Use the existing trusted directory
    configuration and key ID.

    The file must already exist.
    """

    try:
        if environment is None:
            raise ValueError("Missing configuration")

        paths = validate_encrypted_upload_deployment(
            environment
        )

        key_id = environment.get(
            "SECUREVAULT_UPLOAD_KEK_ID"
        )

        if type(key_id) is not str:
            raise ValueError("Missing key ID")

        # The existing key-store helper validates
        # the key ID and constructs the filename.
        key_file = get_protected_key_path(
            paths["key_directory"],
            key_id
        )

        if (
            not key_file.is_file()
            or key_file.is_symlink()
        ):
            raise ValueError(
                "Existing protected key required"
            )

        # Refuse a file that resolves outside
        # the configured protected-key directory.
        if (
            key_file.resolve(strict=True).parent
            != paths["key_directory"]
        ):
            raise ValueError("Unexpected key location")

        result = inspect_protected_key_file_acl(
            key_file
        )

        if (
            type(result) is not dict
            or result.get("dacl_present") is not True
            or type(result.get("broad_read")) is not bool
            or type(result.get("broad_write")) is not bool
            or type(result.get("inherited_ace_count"))
                is not int
            or result["inherited_ace_count"] < 0
        ):
            raise ValueError("Invalid ACL inspection")

        if result["broad_read"] or result["broad_write"]:
            raise ValueError(
                "Protected key file has broad access"
            )

        return {
            "key_file_acl_passed": True,
            "key_file_checked": True,
            "inherited_ace_count": (
                result["inherited_ace_count"]
            )
        }

    except Exception:
        raise EncryptedUploadRegistrationError(
            "Protected key-file ACL preflight failed"
        ) from None


def activate_encrypted_upload_with_key_file_guard(
    app,
    environment
):
    """
    Add individual protected-key-file checks
    before the existing Lesson 72 guard.

    Enabled mode:
      1. Inspect the protected KEK file ACL.
      2. Run the directory ACL checks.
      3. Verify the Windows process identity.
      4. Verify filesystem and database config.
      5. Recover the existing DPAPI key.
      6. Register the JWT-protected upload route.

    Disabled mode never reads the key-file ACL.
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
        validate_protected_key_file_acl(
            environment
        )

    # Preserve the complete existing security
    # chain from Lessons 67 through 72.
    return activate_encrypted_upload_with_acl(
        app,
        environment
    )
