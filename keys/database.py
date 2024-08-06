import sqlite3
from keys import Key
from typing import Optional
from contextlib import contextmanager

# Path to the keys' database:
KEYS_DB_PATH = "../keys.db"


@contextmanager
def keys_database() -> tuple[sqlite3.Connection, sqlite3.Cursor]:
    # Create connection and cursor:
    connection = sqlite3.connect(KEYS_DB_PATH)
    cursor = connection.cursor()

    try:
        # Initialize keys table if one wasn't created already:
        connection.execute('''
            CREATE TABLE IF NOT EXISTS keys 
            (name TEXT PRIMARY KEY NOT NULL, bytes BLOB NOT NULL, password TEXT NOT NULL, salt BLOB NOT NULL);
        ''')
        connection.commit()

        # Return the connection and cursor:
        yield connection, cursor
    finally:
        # Close connection and cursor:
        cursor.close()
        connection.close()


def get_key(key_name: str) -> Optional[Key]:
    """
    Tries to fetch a key from the database, if one exists.
    :param key_name: The name of the key that will be fetched. Not case-sensitive.
    :return: A Key object representing the key in the database if one is found, None otherwise.
    """
    with keys_database() as (connection, cursor):
        # Fetch the data:
        cursor.execute('SELECT name, bytes, password, salt FROM keys WHERE name = ?', (key_name.lower(),))
        key_data = cursor.fetchone()

        # Check if the key was found:
        if len(key_data) > 0:
            return Key(*key_data)
    return None
