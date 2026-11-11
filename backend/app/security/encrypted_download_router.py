"""Authenticated download of existing AES-GCM/DPAPI encrypted documents.

Uses the same validated JWT owner dependency as the encrypted upload router.
No raw KEK, wrapped DEK, filesystem path, or plaintext is logged.
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from backend.app.security.dpapi_document_reader import (
    DocumentRecoveryError,
    read_document_with_dpapi,
)
from backend.app.security.jwt_encrypted_upload_integration import (
    get_verified_upload_owner,
)


def create_jwt_encrypted_download_router(*, db_path, storage_dir, key_directory):
    """Build an isolated router; only register it after upload preflight succeeds."""
    router = APIRouter(tags=["Encrypted Documents"])

    @router.get("/documents/{document_id}/encrypted-content")
    def download_encrypted_document(
        document_id: int,
        authenticated_owner_id: int = Depends(get_verified_upload_owner),
    ):
        if type(document_id) is not int or document_id <= 0:
            raise HTTPException(status_code=404, detail="Document not found")
        if type(authenticated_owner_id) is not int or authenticated_owner_id <= 0:
            raise HTTPException(status_code=401, detail="Authentication required")

        try:
            plaintext = read_document_with_dpapi(
                db_path=db_path,
                storage_dir=storage_dir,
                key_directory=key_directory,
                document_id=document_id,
                owner_user_id=authenticated_owner_id,
            )
        except LookupError:
            # Same response for unknown documents and documents owned by others.
            raise HTTPException(status_code=404, detail="Document not found") from None
        except DocumentRecoveryError:
            # Do not reveal file paths, key IDs, or decryption errors.
            raise HTTPException(status_code=500, detail="Document unavailable") from None

        if type(plaintext) is not bytes:
            raise HTTPException(status_code=500, detail="Document unavailable")

        # No filename header: client uses its own authenticated metadata list.
        return Response(
            content=plaintext,
            media_type="application/octet-stream",
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
                "Content-Disposition": "attachment",
            },
        )

    return router
