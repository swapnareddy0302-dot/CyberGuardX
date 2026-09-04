import os
import sqlite3

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
SQLITE_DATABASE_NAME = os.environ.get(
    "SQLITE_DATABASE_NAME",
    "cyberguardx.db"
)


class DatabaseConnection:
    """
    Database connection for CyberGuardX.

    Local development:
        SQLite

    Vercel deployment:
        PostgreSQL using DATABASE_URL
    """

    def __init__(self):

        self.is_postgres = bool(DATABASE_URL)
        self.connection = None

        if self.is_postgres:

            try:
                import psycopg
                from psycopg.rows import dict_row

                self.connection = psycopg.connect(
                    DATABASE_URL,
                    row_factory=dict_row,
                    connect_timeout=10
                )

            except Exception as exc:

                raise RuntimeError(
                    "Could not connect to PostgreSQL. "
                    "Check DATABASE_URL in Vercel."
                ) from exc

        else:

            self.connection = sqlite3.connect(
                SQLITE_DATABASE_NAME
            )

            self.connection.row_factory = sqlite3.Row

    def execute(self, query, params=()):

        if self.is_postgres:

            # Existing CyberGuardX code uses ?
            # PostgreSQL uses %s.

            query = query.replace(
                "?",
                "%s"
            )

        return self.connection.execute(
            query,
            params
        )

    def commit(self):

        self.connection.commit()

    def rollback(self):

        self.connection.rollback()

    def close(self):

        self.connection.close()


def get_db_connection():

    return DatabaseConnection()


def create_user_table():

    connection = get_db_connection()

    try:

        if connection.is_postgres:

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

        else:

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

        connection.commit()

        print(
            "User database table created successfully."
        )

    finally:

        connection.close()