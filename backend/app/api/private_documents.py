
from pathlib import Path



from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    UploadFile,
    File
)

from backend.app.security.upload_validation import (
    validate_upload,
    MAX_UPLOAD_BYTES
)


from pydantic import BaseModel, Field

import os
from backend.app.security.vault_lifecycle import (
    EncryptedRenameBlocked, VaultLifecycleError,
    reject_encrypted_rename, delete_owned_document_and_ciphertext,
)

from backend.app.api.auth import get_current_user

from backend.app.database.db import DATABASE_PATH


from backend.app.database.owned_document_repository import (
    create_owned_document,
    list_owned_documents,
    get_owned_document,
    update_owned_document,
    delete_owned_document,
    count_owned_documents
)


from backend.app.services.document_service import inspect_document


router = APIRouter(
    prefix="/documents/private",
    tags=["Protected Documents"],
    dependencies=[Depends(get_current_user)]
)


def get_private_db_path():
    """Database location; can be replaced during testing."""
    return DATABASE_PATH


class PrivateDocumentCreate(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=10000)


class PrivateDocumentUpdate(BaseModel):
    filename: str = Field(min_length=1, max_length=255)


@router.post("", status_code=201)
def create_private_document(
    request: PrivateDocumentCreate,
    user=Depends(get_current_user),
    db_path: Path = Depends(get_private_db_path)
):
    metadata = inspect_document(
        request.content.encode("utf-8")
    )

    document_id = create_owned_document(
        owner_user_id=user["user_id"],
        filename=request.filename,
        size_bytes=metadata["size_bytes"],
        sha256=metadata["sha256"],
        db_path=db_path
    )

    
    # Read the record that SQLite just saved.
    # The ownership check is still enforced.
    saved_document = get_owned_document(
        document_id,
        user["user_id"],
        db_path
    )

    if saved_document is None:
        raise HTTPException(
            status_code=500,
            detail="Created document could not be retrieved"
        )

    # Include the timestamp in the API response.
    return {
        "id": saved_document["id"],
        "owner_user_id": saved_document["owner_user_id"],
        "filename": saved_document["filename"],
        "size_bytes": saved_document["size_bytes"],
        "sha256": saved_document["sha256"],
        "created_at": saved_document.get("created_at")
    }




@router.get("")
def list_private_documents(
    user=Depends(get_current_user),
    db_path: Path = Depends(get_private_db_path),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0)
):
    """Return one page of documents with pagination details."""

    owner_id = user["user_id"]

    documents = list_owned_documents(
        owner_user_id=owner_id,
        db_path=db_path,
        limit=limit,
        offset=offset
    )

    total = count_owned_documents(
        owner_user_id=owner_id,
        db_path=db_path
    )

    has_more = offset + len(documents) < total

    return {
        "documents": documents,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": has_more
    }


@router.get("/{document_id}")
def read_private_document(
    document_id: int,
    user=Depends(get_current_user),
    db_path: Path = Depends(get_private_db_path)
):
    document = get_owned_document(
        document_id,
        user["user_id"],
        db_path
    )

    if document is None:
        raise HTTPException(
            status_code=404,
            detail="Document not found"
        )

    return document


@router.patch("/{document_id}")
def rename_private_document(
    document_id: int,
    request: PrivateDocumentUpdate,
    user=Depends(get_current_user),
    db_path: Path = Depends(get_private_db_path)
):
    try:
        reject_encrypted_rename(document_id, user["user_id"], db_path)
    except EncryptedRenameBlocked:
        raise HTTPException(status_code=409, detail="Encrypted document cannot be renamed") from None
    except (VaultLifecycleError, ValueError):
        raise HTTPException(status_code=503, detail="Document safety check unavailable") from None

    updated = update_owned_document(
        document_id,
        user["user_id"],
        request.filename,
        db_path
    )

    if not updated:
        raise HTTPException(
            status_code=404,
            detail="Document not found"
        )

    return {
        "id": document_id,
        "filename": request.filename,
        "message": "Document updated successfully"
    }


@router.delete("/{document_id}")
def remove_private_document(
    document_id: int,
    user=Depends(get_current_user),
    db_path: Path = Depends(get_private_db_path)
):
    try:
        deleted = delete_owned_document_and_ciphertext(
            document_id=document_id,
            owner_user_id=user["user_id"],
            db_path=db_path,
            storage_dir=os.environ.get("SECUREVAULT_UPLOAD_STORAGE_DIR"),
        )
    except (VaultLifecycleError, ValueError):
        raise HTTPException(status_code=503, detail="Safe document deletion unavailable") from None


    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="Document not found"
        )

    return {
        "id": document_id,
        "message": "Document deleted successfully"
    }


@router.post("/upload/check")
async def check_private_upload(
    file: UploadFile = File(...),
    user=Depends(get_current_user)
):
    """
    Inspect one uploaded text file.

    Requires JWT authentication.
    Does NOT save the file or its metadata.
    """

    try:
        # Read at most one byte beyond our accepted limit.
        # This allows us to reject oversized content.
        content = await file.read(MAX_UPLOAD_BYTES + 1)

        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail="File exceeds the 1 MiB limit"
            )

        # Apply our Lesson 36 validator.
        try:
            metadata = validate_upload(
                file.filename,
                content
            )

        except ValueError as error:
            raise HTTPException(
                status_code=400,
                detail=str(error)
            ) from error

        return {
            "message": "UPLOAD VALIDATION SUCCESSFUL",
            "user_id": user["user_id"],
            "filename": metadata["filename"],
            "size_bytes": metadata["size_bytes"],
            "sha256": metadata["sha256"],
            "stored": False
        }

    finally:
        # Always close the temporary uploaded file.
        await file.close()
