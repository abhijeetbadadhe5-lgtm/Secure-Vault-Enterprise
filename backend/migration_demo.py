
import sqlite3
from contextlib import closing

from backend.app.database.db import DATABASE_PATH
from backend.app.database.migrations.migration_001 import (
    run_migration
)


def main():

    print("=== SECUREVAULT DATABASE MIGRATION ===")

    print("Database:", DATABASE_PATH)

    result = run_migration()

    print(result)

    # Check which columns now exist
    with closing(sqlite3.connect(DATABASE_PATH)) as connection:

        columns = connection.execute(
            "PRAGMA table_info(owned_documents)"
        ).fetchall()

        print()
        print("=== DATABASE COLUMNS ===")

        for column in columns:
            print(column[1])

        count = connection.execute(
            "SELECT COUNT(*) FROM owned_documents"
        ).fetchone()[0]

        print()
        print("Existing document records:", count)

        history = connection.execute(
            "SELECT version, name FROM schema_migrations"
        ).fetchall()

        print("Applied migrations:", history)

    print()
    print("DATABASE MIGRATION CHECK SUCCESSFUL")


if __name__ == "__main__":
    main()
