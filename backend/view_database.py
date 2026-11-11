
from backend.app.database.document_repository import list_documents


def main():

    print("=== SECUREVAULT SAVED DOCUMENTS ===")

    documents = list_documents()

    if not documents:
        print("No documents saved yet.")
        return

    for document in documents:

        print()
        print("Document ID:", document["id"])
        print("Filename:", document["filename"])
        print("Owner:", document["owner"])
        print("Size:", document["size_bytes"], "bytes")
        print("SHA-256:", document["sha256"])

    print()
    print("Total records:", len(documents))
    print("DATABASE RECORDS DISPLAYED SUCCESSFULLY")


if __name__ == "__main__":
    main()
