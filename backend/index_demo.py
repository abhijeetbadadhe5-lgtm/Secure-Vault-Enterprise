
import sqlite3
from contextlib import closing

from backend.app.database.db import DATABASE_PATH

from backend.app.database.migrations.migration_002 import (
    run_migration
)


def main():

    print("=== SECUREVAULT INDEX MIGRATION ===")

    print("Database:", DATABASE_PATH)

    result = run_migration()

    print(result)

    with closing(sqlite3.connect(DATABASE_PATH)) as connection:

        indexes = connection.execute(
            "PRAGMA index_list(owned_documents)"
        ).fetchall()

        print()
        print("=== DOCUMENT INDEXES ===")

        for index in indexes:
            print(index[1])

        history == connection.execute(
            """
            SELECT version, name
            FROM schema_migrations
            ORDER BY version
            """
        ).fetchall()

        print()
        print("Applied migrations:", history)

        document_count = connection.execute(
            "SELECT COUNT(*) FROM owned_documents"
        ).fetchone()[0]

        print("Document records:", document_count)

    print()
    print("INDEX MIGRATION CHECK SUCCESSFUL")


if __name__ == "__main__":
    main()
