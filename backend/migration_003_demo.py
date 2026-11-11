
import sqlite3

from backend.app.database.db import DATABASE_PATH
from backend.app.database.migrations.migration_003 import (
    apply_migration_003
)


def main():
    print("SECUREVAULT LESSON 45")
    print("---------------------")

    result = apply_migration_003(DATABASE_PATH)

    print("Migration result:", result)

    with sqlite3.connect(DATABASE_PATH) as connection:
        history = connection.execute(
            """
            SELECT version, name
            FROM schema_migrations
            ORDER BY version
            """
        ).fetchall()

        document_count = connection.execute(
            "SELECT COUNT(*) FROM owned_documents"
        ).fetchone()[0]

        encrypted_count = connection.execute(
            "SELECT COUNT(*) FROM encrypted_document_keys"
        ).fetchone()[0]

    print("Migration history:", history)
    print("Existing document count:", document_count)
    print("Encrypted key records:", encrypted_count)


if __name__ == "__main__":
    main()
