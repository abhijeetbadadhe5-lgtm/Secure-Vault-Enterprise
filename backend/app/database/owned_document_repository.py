
import sqlite3
from contextlib import closing

from backend.app.database.db import (
    DATABASE_PATH,
    initialize_database
)


def initialize_owned_documents(db_path=DATABASE_PATH):
    """Create a table for documents linked to registered users."""

    initialize_database(db_path)

    with closing(sqlite3.connect(db_path)) as connection:

        with connection:

            connection.execute("""
                CREATE TABLE IF NOT EXISTS owned_documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_user_id INTEGER NOT NULL,
                    filename TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL
                        CHECK(size_bytes >= 0),
                    sha256 TEXT NOT NULL,
                    FOREIGN KEY (owner_user_id)
                        REFERENCES users(id)
                )
            """)



def create_owned_document(
    owner_user_id,
    filename,
    size_bytes,
    sha256,
    db_path=DATABASE_PATH
):
    """Save document metadata and record creation time if available."""

    initialize_owned_documents(db_path)

    with closing(sqlite3.connect(db_path)) as connection:

        connection.execute("PRAGMA foreign_keys = ON")

        # Check whether migration 001 added created_at.
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(owned_documents)"
            ).fetchall()
        }

        with connection:

            if "created_at" in columns:

                cursor = connection.execute(
                    """
                    INSERT INTO owned_documents
                    (
                        owner_user_id,
                        filename,
                        size_bytes,
                        sha256,
                        created_at
                    )
                    VALUES (
                        ?, ?, ?, ?,
                        strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    )
                    """,
                    (
                        owner_user_id,
                        filename,
                        size_bytes,
                        sha256
                    )
                )

            else:

                # Compatibility with older temporary test databases.
                cursor = connection.execute(
                    """
                    INSERT INTO owned_documents
                    (
                        owner_user_id,
                        filename,
                        size_bytes,
                        sha256
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        owner_user_id,
                        filename,
                        size_bytes,
                        sha256
                    )
                )

            return cursor.lastrowid




def list_owned_documents(
    owner_user_id,
    db_path=DATABASE_PATH,
    limit=100,
    offset=0
):
    """List one user's documents with pagination."""

    initialize_owned_documents(db_path)

    if not isinstance(limit, int) or isinstance(limit, bool):
        raise ValueError("limit must be an integer")

    if not isinstance(offset, int) or isinstance(offset, bool):
        raise ValueError("offset must be an integer")

    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")

    if offset < 0:
        raise ValueError("offset cannot be negative")

    with closing(sqlite3.connect(db_path)) as connection:

        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT *
            FROM owned_documents
            WHERE owner_user_id = ?
            ORDER BY id ASC
            LIMIT ? OFFSET ?
            """,
            (owner_user_id, limit, offset)
        ).fetchall()

        return [dict(row) for row in rows]


def get_owned_document(
    document_id,
    owner_user_id,
    db_path=DATABASE_PATH
):
    """Return a record only if it belongs to the user."""

    initialize_owned_documents(db_path)

    with closing(sqlite3.connect(db_path)) as connection:

        connection.row_factory = sqlite3.Row

        row = connection.execute(
            """
            SELECT * FROM owned_documents
            WHERE id = ? AND owner_user_id = ?
            """,
            (document_id, owner_user_id)
        ).fetchone()

        return dict(row) if row else None


def update_owned_document(
    document_id,
    owner_user_id,
    new_filename,
    db_path=DATABASE_PATH
):
    """Update only a record owned by this user."""

    initialize_owned_documents(db_path)

    with closing(sqlite3.connect(db_path)) as connection:

        with connection:

            cursor = connection.execute(
                """
                UPDATE owned_documents
                SET filename = ?
                WHERE id = ? AND owner_user_id = ?
                """,
                (new_filename, document_id, owner_user_id)
            )

            return cursor.rowcount > 0


def delete_owned_document(
    document_id,
    owner_user_id,
    db_path=DATABASE_PATH
):
    """Delete only a record owned by this user."""

    initialize_owned_documents(db_path)

    with closing(sqlite3.connect(db_path)) as connection:

        with connection:

            cursor = connection.execute(
                """
                DELETE FROM owned_documents
                WHERE id = ? AND owner_user_id = ?
                """,
                (document_id, owner_user_id)
            )

            return cursor.rowcount > 0

        
def count_owned_documents(
    owner_user_id,
    db_path=DATABASE_PATH
):
    """Count only documents owned by this user."""

    initialize_owned_documents(db_path)

    with closing(sqlite3.connect(db_path)) as connection:

        row = connection.execute(
            """
            SELECT COUNT(*)
            FROM owned_documents
            WHERE owner_user_id = ?
            """,
            (owner_user_id,)
        ).fetchone()

        return row[0]

