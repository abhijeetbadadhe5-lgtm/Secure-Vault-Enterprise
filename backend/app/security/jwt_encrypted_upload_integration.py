
from fastapi import Depends, HTTPException

from backend.app.api.auth import (
    get_current_user
)

from backend.app.security.encrypted_upload_router import (
    create_encrypted_upload_router
)


def get_verified_upload_owner(
    user=Depends(get_current_user)
):
    """
    Extract an authenticated user ID.

    The existing get_current_user dependency
    performs real JWT verification and account
    lookup before this function runs.

    Never read owner_user_id from the client.
    """

    if type(user) is not dict:
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )

    user_id = user.get("user_id")

    # Reject booleans, strings, zero and
    # negative numbers.
    if (
        type(user_id) is not int
        or user_id <= 0
    ):
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )

    return user_id


def create_jwt_encrypted_upload_router(
    *,
    db_path,
    storage_dir,
    key_directory,
    key_id
):
    """
    Build the Lesson 65 router using the
    existing SecureVault JWT authentication.

    The router does not mount itself into
    the main application.

    All paths and the KEK identifier must
    come from trusted backend configuration.
    """

    return create_encrypted_upload_router(
        db_path=db_path,
        storage_dir=storage_dir,
        key_directory=key_directory,
        key_id=key_id,
        authenticated_owner_dependency=(
            get_verified_upload_owner
        )
    )
