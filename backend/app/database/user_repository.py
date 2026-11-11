
import sqlite3
from contextlib import closing

from backend.app.database.db import (
    DATABASE_PATH,
    initialize_database
)

from backend.app.security.passwords import (
    hash_password,
    verify_password
)


def register_user(username, password, db_path=DATABASE_PATH):
    """Register a user and store their password hash."""

    initialize_database(db_path)

    if not username or not username.strip():
        raise ValueError("Username cannot be empty.")

    if not password:
        raise ValueError("Password cannot be empty.")

    # Hash the password before storing it
    hashed_password = hash_password(password)

    with closing(sqlite3.connect(db_path)) as connection:

        try:
            with connection:

                cursor = connection.execute(
                    """
                    INSERT INTO users
                    (username, password_hash)
                    VALUES (?, ?)
                    """,
                    (username, hashed_password)
                )

                return cursor.lastrowid

        except sqlite3.IntegrityError:
            raise ValueError(
                "Username already exists."
            ) from None


def authenticate_user(
    username,
    password,
    db_path=DATABASE_PATH
):
    """Check the saved account password."""

    initialize_database(db_path)

    with closing(sqlite3.connect(db_path)) as connection:

        connection.row_factory = sqlite3.Row

        row = connection.execute(
            """
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        if row is None:
            return None

        if not verify_password(row["password_hash"], password):
            return None

        return {
            "id": row["id"],
            "username": row["username"]
        }


def get_user_by_id(user_id, db_path=DATABASE_PATH):
    """Retrieve a user without exposing the password hash."""

    initialize_database(db_path)

    with closing(sqlite3.connect(db_path)) as connection:

        connection.row_factory = sqlite3.Row

        row = connection.execute(
            """
            SELECT id, username
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

        if row is None:
            return None

        return dict(row)
