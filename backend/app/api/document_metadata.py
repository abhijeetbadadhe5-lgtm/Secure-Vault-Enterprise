
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.app.services.document_service import inspect_document


from backend.app.database.document_repository import (
    save_document_metadata,
    get_document_metadata,
    list_documents,
    update_document_filename,
    delete_document_metadata
)



router = APIRouter(
    prefix="/documents/metadata",
    tags=["Document Metadata"]
)


class DocumentMetadataRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    owner: str = Field(min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=10000)


@router.post("", status_code=201)
def create_document_metadata(
    document: DocumentMetadataRequest
):
    # Convert text to bytes
    document_bytes = document.content.encode("utf-8")

    # Calculate size and SHA-256
    metadata = inspect_document(document_bytes)

    # Save metadata to SQLite
    document_id = save_document_metadata(
        filename=document.filename,
        owner=document.owner,
        size_bytes=metadata["size_bytes"],
        sha256=metadata["sha256"]
    )

    return {
        "id": document_id,
        "filename": document.filename,
        "owner": document.owner,
        "size_bytes": metadata["size_bytes"],
        "sha256": metadata["sha256"],
        "message": "Document metadata saved successfully"
    }


@router.get("")
def get_all_document_metadata():
    return {
        "documents": list_documents()
    }


@router.get("/{document_id}")
def get_single_document_metadata(document_id: int):

    if document_id < 1:
        raise HTTPException(
            status_code=422,
            detail="Document ID must be positive"
        )

    document = get_document_metadata(document_id)

    if document is None:
        raise HTTPException(
            status_code=404,
            detail="Document not found"
        )

    return document



class DocumentFilenameUpdate(BaseModel):
    filename: str = Field(min_length=1, max_length=255)


@router.patch("/{document_id}")
def update_document_api(
    document_id: int,
    update: DocumentFilenameUpdate
):
    if document_id < 1:
        raise HTTPException(
            status_code=422,
            detail="Document ID must be positive"
        )

    updated = update_document_filename(
        document_id,
        update.filename
    )

    if not updated:
        raise HTTPException(
            status_code=404,
            detail="Document not found"
        )

    return {
        "id": document_id,
        "filename": update.filename,
        "message": "Document filename updated successfully"
    }


@router.delete("/{document_id}")
def delete_document_api(document_id: int):

    if document_id < 1:
        raise HTTPException(
            status_code=422,
            detail="Document ID must be positive"
        )

    deleted = delete_document_metadata(document_id)

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="Document not found"
        )

    return {
        "id": document_id,
        "message": "Document metadata deleted successfully"
    }
