import sqlite3


DATABASE_NAME = "cyberguardx.db"


def get_db_connection():

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    connection.row_factory = sqlite3.Row

    return connection


def create_user_table():

    connection = get_db_connection()

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT NOT NULL UNIQUE,

            email TEXT NOT NULL UNIQUE,

            password TEXT NOT NULL

        )
        """
    )

    connection.commit()

    connection.close()


if __name__ == "__main__":

    create_user_table()

    print(
        "Database created successfully!"
    )