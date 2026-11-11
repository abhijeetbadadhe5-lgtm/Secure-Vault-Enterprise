
import sqlite3

from pathlib import Path


MIGRATION_VERSION = 3
MIGRATION_NAME = "create_encrypted_document_keys"


def apply_migration_003(db_path):
    """
    Add a table linking owned documents to encrypted storage.

    Existing documents and their metadata are preserved.

    This migration is transactional and idempotent.
    """

    db_path = Path(db_path)

    # Never silently create an unexpected database.
    if not db_path.is_file():
        raise FileNotFoundError(
            "Existing SQLite database not found"
        )

    connection = sqlite3.connect(db_path)

    try:
        connection.execute("PRAGMA foreign_keys = ON")

        # Acquire a write transaction before inspecting
        # and changing the schema.
        connection.execute("BEGIN IMMEDIATE")

        # Require the previous migration history.
        history_table = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'schema_migrations'
            """
        ).fetchone()

        if history_table is None:
            raise RuntimeError(
                "Migration history table is missing"
            )

        versions = {
            row[0]
            for row in connection.execute(
                "SELECT version FROM schema_migrations"
            ).fetchall()
        }

        if MIGRATION_VERSION in versions:
            connection.commit()
            return "ALREADY APPLIED"

        if not {1, 2}.issubset(versions):
            raise RuntimeError(
                "Migrations 001 and 002 must exist first"
            )

        owned_table = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'owned_documents'
            """
        ).fetchone()

        if owned_table is None:
            raise RuntimeError(
                "Owned documents table is missing"
            )

        # Do not silently adopt an unknown preexisting table.
        existing_new_table = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'encrypted_document_keys'
            """
        ).fetchone()

        if existing_new_table is not None:
            raise RuntimeError(
                "Encrypted key table exists without migration record"
            )

        # Create the new table without altering old records.
        connection.execute(
            """
            CREATE TABLE encrypted_document_keys (
                document_id INTEGER PRIMARY KEY,

                storage_id TEXT NOT NULL UNIQUE
                    CHECK (
                        length(storage_id) = 32
                        AND storage_id
                            NOT GLOB '*[^0-9a-f]*'
                    ),

                key_id TEXT NOT NULL
                    CHECK (
                        length(key_id) BETWEEN 1 AND 64
                        AND key_id
                            NOT GLOB '*[^A-Za-z0-9_-]*'
                    ),

                wrap_nonce BLOB NOT NULL
                    CHECK (
                        typeof(wrap_nonce) = 'blob'
                        AND length(wrap_nonce) = 12
                    ),

                wrapped_dek BLOB NOT NULL
                    CHECK (
                        typeof(wrapped_dek) = 'blob'
                        AND length(wrapped_dek) = 48
                    ),

                created_at TEXT NOT NULL DEFAULT (
                    strftime(
                        '%Y-%m-%dT%H:%M:%SZ',
                        'now'
                    )
                ),

                FOREIGN KEY (document_id)
                    REFERENCES owned_documents(id)
                    ON DELETE CASCADE
            )
            """
        )

        # Only record success after table creation.
        connection.execute(
            """
            INSERT INTO schema_migrations
                (version, name)
            VALUES (?, ?)
            """,
            (MIGRATION_VERSION, MIGRATION_NAME)
        )

        connection.commit()

        return "MIGRATION APPLIED SUCCESSFULLY"

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()
