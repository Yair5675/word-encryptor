import keys
import sqlite3
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


def get_key(key_name: str) -> Optional[keys.Key]:
    """
    Tries to fetch a key from the database, if one exists.
    :param key_name: The name of the key that will be fetched. Not case-sensitive.
    :return: A Key object representing the key in the database if one is found, None otherwise.
    """
    with keys_database() as (connection, cursor):
        # Fetch the data:
        cursor.execute('SELECT name, bytes, password, salt FROM keys WHERE name = ?;', (key_name.lower(),))
        key_data = cursor.fetchone()

        # Check if the key was found:
        if len(key_data) > 0:
            return keys.Key(*key_data)
    return None


def add_key(key_name: str, key_password: str, key_length: int, iterations: int) -> None:
    """
    Adds a new key to the database based on the given parameters. If the key_name parameter matches
    the name of a key already stored in the database, the old key will be replaced with a new one.
    :param key_name: The name of the new key which will be created, not case-sensitive.
    :param key_password: The raw password that the key will be based on.
    :param key_length: The length of the key (in bytes).
    :param iterations: Number of iteration to create the encryption key (a larger number is more
                       secure but slower).
    """
    # Derive a new key:
    key = keys.derive_key(key_password, key_name, key_length=key_length, iterations=iterations)

    # Save the key to the database:
    with keys_database() as (connection, cursor):
        cursor.execute(
            'INSERT OR REPLACE INTO keys (name, bytes, password, salt) VALUES (?, ?, ?, ?);',
            (key.name, key.bytes, key.password, key.salt)
        )
        connection.commit()


def remove_key(key_name: str) -> None:
    """
    Removes a key from the database based on the key's name.
    :param key_name: The name of the key that will be removed from the database, not case-sensitive.
    """
    with keys_database() as (connection, cursor):
        cursor.execute("DELETE FROM keys WHERE name = ?;", (key_name.lower(),))
        connection.commit()
