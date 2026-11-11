
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request
)

from backend.app.security.encrypted_upload_preflight import (
    MAX_PRACTICE_UPLOAD_BYTES
)

from backend.app.security.encrypted_upload_service import (
    EncryptedUploadServiceError,
    UploadOwnershipError,
    store_encrypted_upload
)


def create_encrypted_upload_router(
    *,
    db_path,
    storage_dir,
    key_directory,
    key_id,
    authenticated_owner_dependency
):
    """
    Create an isolated encrypted-upload router.

    The caller MUST supply an authentication
    dependency that validates the user first.

    Do not use a request-supplied user ID.

    This factory does not mount itself into
    the existing SecureVault FastAPI app.
    """

    if not callable(authenticated_owner_dependency):
        raise ValueError(
            "Trusted authentication dependency required"
        )

    router = APIRouter()

    @router.post(
        "/documents/{document_id}/encrypted-content",
        status_code=201
    )
    async def upload_encrypted_document(
        document_id: int,
        request: Request,
        filename: str = Query(...),
        authenticated_owner_id: int = Depends(
            authenticated_owner_dependency
        )
    ):
        """
        Receive a bounded binary request body,
        then call the Lesson 64 upload service.
        """

        # Step 1: Never trust an owner ID
        # supplied directly by an HTTP client.
        if (
            type(authenticated_owner_id) is not int
            or authenticated_owner_id <= 0
        ):
            raise HTTPException(
                status_code=401,
                detail="Authentication required"
            )

        # Step 2: Accept only raw binary content.
        content_type = request.headers.get(
            "content-type", ""
        ).split(";", 1)[0].strip().lower()

        if content_type != "application/octet-stream":
            raise HTTPException(
                status_code=415,
                detail="Unsupported media type"
            )

        # Step 3: Read incoming bytes incrementally.
        # Stop as soon as the configured limit
        # is exceeded.
        chunks = []
        total_bytes = 0

        async for chunk in request.stream():

            total_bytes += len(chunk)

            if total_bytes > MAX_PRACTICE_UPLOAD_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail="Upload exceeds size limit"
                )

            if chunk:
                chunks.append(chunk)

        if total_bytes == 0:
            raise HTTPException(
                status_code=400,
                detail="Empty upload rejected"
            )

        # The data is held in memory for encryption.
        # This router never saves a plaintext file.
        content = b"".join(chunks)

        # Step 4: Authorize using the trusted
        # identity supplied by the dependency.
        try:
            result = store_encrypted_upload(
                db_path=db_path,
                storage_dir=storage_dir,
                key_directory=key_directory,
                document_id=document_id,
                authenticated_owner_id=(
                    authenticated_owner_id
                ),
                filename=filename,
                content=content,
                key_id=key_id
            )

        except UploadOwnershipError:
            # Do not reveal another user's
            # document existence.
            raise HTTPException(
                status_code=404,
                detail="Document not found"
            ) from None

        except EncryptedUploadServiceError:
            raise HTTPException(
                status_code=400,
                detail="Encrypted upload rejected"
            ) from None

        # Step 5: Return metadata only.
        # Never include plaintext or encryption keys.
        return {
            "stored": True,
            "document_id": result["document_id"],
            "storage_id": result["storage_id"],
            "size_bytes": result["size_bytes"],
            "encrypted": True
        }

    return router
