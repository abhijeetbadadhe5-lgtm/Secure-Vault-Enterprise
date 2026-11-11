
from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.app.services.document_service import inspect_document


router = APIRouter(prefix="/documents", tags=["Documents"])


class DocumentRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=10000)


@router.post("/inspect")
def inspect_document_api(document: DocumentRequest):

    document_bytes = document.content.encode("utf-8")

    result = inspect_document(document_bytes)

    return {
        "filename": document.filename,
        "size_bytes": result["size_bytes"],
        "sha256": result["sha256"],
        "message": "Document inspected successfully"
    }
