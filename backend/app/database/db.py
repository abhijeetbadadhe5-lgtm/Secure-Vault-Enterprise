

import sqlite3
from pathlib import Path
from contextlib import closing


BACKEND_DIR = Path(__file__).resolve().parents[2]

DATABASE_PATH = BACKEND_DIR / "data" / "securevault.db"


def initialize_database(db_path=DATABASE_PATH):
    """Create the document database and table."""

    db_path = Path(db_path)

    db_path.parent.mkdir(parents=True, exist_ok=True)

    # closing() ensures the connection is closed
    with closing(sqlite3.connect(db_path)) as connection:

        with connection:

            connection.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL
                        CHECK(size_bytes >= 0),
                    sha256 TEXT NOT NULL
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL
                )
            """)
