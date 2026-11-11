
from backend.app.core.config import show_configuration
from backend.app.services.document_service import inspect_document


def main():
    print("=== SECUREVAULT BACKEND ===")

    show_configuration()

    print()
    print("=== DOCUMENT INSPECTION ===")

    sample_document = b"SecureVault Example Document"

    result = inspect_document(sample_document)

    print("Document size:", result["size_bytes"], "bytes")
    print("SHA-256:", result["sha256"])

    print()
    print("BACKEND STRUCTURE WORKING SUCCESSFULLY")


if __name__ == "__main__":
    main()
