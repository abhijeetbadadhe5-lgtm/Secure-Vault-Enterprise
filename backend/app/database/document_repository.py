

import sqlite3
from contextlib import closing

from backend.app.database.db import (
    DATABASE_PATH,
    initialize_database
)


def save_document_metadata(
    filename,
    owner,
    size_bytes,
    sha256,
    db_path=DATABASE_PATH
):
    """Save one document metadata record."""

    initialize_database(db_path)

    with closing(sqlite3.connect(db_path)) as connection:

        with connection:

            cursor = connection.execute(
                """
                INSERT INTO documents
                (filename, owner, size_bytes, sha256)
                VALUES (?, ?, ?, ?)
                """,
                (filename, owner, size_bytes, sha256)
            )

            return cursor.lastrowid


def get_document_metadata(
    document_id,
    db_path=DATABASE_PATH
):
    """Retrieve one document record by ID."""

    initialize_database(db_path)

    with closing(sqlite3.connect(db_path)) as connection:

        connection.row_factory = sqlite3.Row

        cursor = connection.execute(
            "SELECT * FROM documents WHERE id = ?",
            (document_id,)
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)


def list_documents(db_path=DATABASE_PATH):
    """Retrieve all document records."""

    initialize_database(db_path)

    with closing(sqlite3.connect(db_path)) as connection:

        connection.row_factory = sqlite3.Row

        cursor = connection.execute(
            "SELECT * FROM documents ORDER BY id"
        )

        return [dict(row) for row in cursor.fetchall()]



def update_document_filename(
    document_id,
    new_filename,
    db_path=DATABASE_PATH
):
    """Change the filename of an existing record."""

    initialize_database(db_path)

    with closing(sqlite3.connect(db_path)) as connection:

        with connection:

            cursor = connection.execute(
                """
                UPDATE documents
                SET filename = ?
                WHERE id = ?
                """,
                (new_filename, document_id)
            )

            return cursor.rowcount > 0


def delete_document_metadata(
    document_id,
    db_path=DATABASE_PATH
):
    """Delete one document metadata record."""

    initialize_database(db_path)

    with closing(sqlite3.connect(db_path)) as connection:

        with connection:

            cursor = connection.execute(
                "DELETE FROM documents WHERE id = ?",
                (document_id,)
            )

            return cursor.rowcount > 0
