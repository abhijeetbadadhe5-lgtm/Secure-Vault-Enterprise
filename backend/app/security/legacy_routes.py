
from fastapi import HTTPException


def reject_legacy_document_access():
    """
    Reject access to retired document endpoints.

    The old endpoints are preserved in source code,
    but cannot be used in the normal running API.
    """

    raise HTTPException(
        status_code=410,
        detail=(
            "This legacy document endpoint has been retired. "
            "Use the protected /documents/private API."
        )
    )
