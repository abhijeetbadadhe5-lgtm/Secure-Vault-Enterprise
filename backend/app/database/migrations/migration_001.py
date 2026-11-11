
import sqlite3
from contextlib import closing
from pathlib import Path

from backend.app.database.db import DATABASE_PATH


MIGRATION_VERSION = 1
MIGRATION_NAME = "add_owned_document_created_at"


def run_migration(db_path=DATABASE_PATH):
    """Add a nullable created_at column safely."""

    db_path = Path(db_path)

    if not db_path.is_file():
        raise FileNotFoundError(
            f"Database file does not exist: {db_path}"
        )

    with closing(sqlite3.connect(db_path)) as connection:

        # Begin a write transaction.
        # If anything fails, changes are rolled back.
        with connection:

            connection.execute("BEGIN IMMEDIATE")

            # Make sure our original table exists.
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
                    "owned_documents table not found. "
                    "Migration stopped without changing documents."
                )

            # Store information about migrations already applied.
            connection.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                        DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                )
            """)

            existing = connection.execute(
                """
                SELECT version
                FROM schema_migrations
                WHERE version = ?
                """,
                (MIGRATION_VERSION,)
            ).fetchone()

            # Get existing column names.
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(owned_documents)"
                ).fetchall()
            }

            if existing is not None:
                if "created_at" not in columns:
                    raise RuntimeError(
                        "Migration is recorded, but column is missing."
                    )

                return "ALREADY APPLIED"

            if "created_at" in columns:
                raise RuntimeError(
                    "created_at column already exists, but "
                    "migration history is missing. "
                    "Manual review required."
                )

            # Add a new column without losing existing rows.
            connection.execute("""
                ALTER TABLE owned_documents
                ADD COLUMN created_at TEXT
            """)

            # Record the successful migration.
            connection.execute(
                """
                INSERT INTO schema_migrations (version, name)
                VALUES (?, ?)
                """,
                (MIGRATION_VERSION, MIGRATION_NAME)
            )

            return "MIGRATION APPLIED SUCCESSFULLY"
