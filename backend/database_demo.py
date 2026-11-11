
from backend.app.database.db import initialize_database

from backend.app.database.document_repository import (
    save_document_metadata,
    get_document_metadata,
    list_documents
)

from backend.app.services.document_service import (
    inspect_document
)


def main():

    print("=== SECUREVAULT DATABASE LESSON ===")

    initialize_database()

    print("DATABASE INITIALIZED SUCCESSFULLY")

    # Fictional document used for practice
    filename = "practice_report.txt"
    owner = "Alice"
    content = b"Hello SecureVault Database"

    # Calculate metadata using existing service
    metadata = inspect_document(content)

    # Save only document metadata
    document_id = save_document_metadata(
        filename=filename,
        owner=owner,
        size_bytes=metadata["size_bytes"],
        sha256=metadata["sha256"]
    )

    print("DOCUMENT METADATA SAVED SUCCESSFULLY")
    print("Document ID:", document_id)

    # Retrieve the saved record
    saved_document = get_document_metadata(document_id)

    print()
    print("=== RETRIEVED RECORD ===")
    print("Filename:", saved_document["filename"])
    print("Owner:", saved_document["owner"])
    print("Size:", saved_document["size_bytes"], "bytes")
    print("SHA-256:", saved_document["sha256"])

    # Show number of saved records
    all_documents = list_documents()

    print()
    print("Total saved records:", len(all_documents))
    print("DATABASE DEMONSTRATION SUCCESSFUL")


if __name__ == "__main__":
    main()
