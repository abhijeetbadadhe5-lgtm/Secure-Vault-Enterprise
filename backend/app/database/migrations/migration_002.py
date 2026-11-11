
import sqlite3
from pathlib import Path
from contextlib import closing

from backend.app.database.db import DATABASE_PATH


MIGRATION_VERSION = 2
MIGRATION_NAME = "index_owned_documents_owner"

INDEX_NAME = "idx_owned_documents_owner_user_id"


def run_migration(db_path=DATABASE_PATH):
    """
    Create an index on owner_user_id.

    Safe to run again after it has already succeeded.
    """

    db_path = Path(db_path)

    if not db_path.is_file():
        raise FileNotFoundError(
            f"Database does not exist: {db_path}"
        )

    with closing(sqlite3.connect(db_path)) as connection:
        with connection:

            connection.execute("BEGIN IMMEDIATE")

            # Check the document table exists.
            table = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                  AND name = 'owned_documents'
                """
            ).fetchone()

            if table is None:
                raise RuntimeError(
                    "owned_documents table is missing"
                )

            # Migration 001 must have run first.
            migration_table = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                  AND name = 'schema_migrations'
                """
            ).fetchone()

            if migration_table is None:
                raise RuntimeError(
                    "Run migration 001 before migration 002"
                )

            previous = connection.execute(
                """
                SELECT version FROM schema_migrations
                WHERE version = 1
                """
            ).fetchone()

            if previous is None:
                raise RuntimeError(
                    "Migration 001 has not been applied"
                )

            # Check for an existing index.
            index = connection.execute(
                """
                SELECT name, tbl_name
                FROM sqlite_master
                WHERE type = 'index'
                  AND name = ?
                """,
                (INDEX_NAME,)
            ).fetchone()

            applied = connection.execute(
                """
                SELECT version FROM schema_migrations
                WHERE version = ?
                """,
                (MIGRATION_VERSION,)
            ).fetchone()

            if applied is not None:
                if index is None or index[1] != "owned_documents":
                    raise RuntimeError(
                        "Migration 002 is recorded, "
                        "but its index is missing or incorrect"
                    )

                return "ALREADY APPLIED"

            if index is not None:
                raise RuntimeError(
                    "Index exists without migration history. "
                    "Manual review required."
                )

            # Create an index for owner lookups.
            connection.execute("""
                CREATE INDEX idx_owned_documents_owner_user_id
                ON owned_documents (owner_user_id)
            """)

            # Record migration 002.
            connection.execute(
                """
                INSERT INTO schema_migrations (version, name)
                VALUES (?, ?)
                """,
                (MIGRATION_VERSION, MIGRATION_NAME)
            )

            return "MIGRATION 002 APPLIED SUCCESSFULLY"
