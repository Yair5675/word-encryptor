import os
import typer
import sqlite3
from typing import Optional
from collections import namedtuple
from contextlib import contextmanager
from rich.prompt import Confirm, Prompt
from typing_extensions import Annotated
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# The part of the app responsible for keys handling:
keys_app = typer.Typer()

# A key datatype that will save all necessary information:
Key = namedtuple("Key", ["bytes", "password", "salt"])

# The salt size used in Key generation (in bytes):
SALT_SIZE = 32

# Path to the keys' database:
KEYS_DB_PATH = "keys.db"


def derive_key(password: str, salt: Optional[bytes] = None, key_length: int = 32, iterations: int = 10_000) -> Key:
    """
    Creates an encryption key based on the given password and salt parameters.
    :param password: A password chosen by the encryptor, will be used to determine the value of the encryption key.
    :param salt: A random collection of bytes that will be added to the creation of the key to make it more secure. If not given, the salt will be generated randomly.
    :param key_length: The length of the key in bytes, default is 32.
    :param iterations: Number of iteration to create the encryption key (a larger number is more secure but slower). Default is 10_000.
    :return: The encryption key that was generated with the password and salt parameters.
    """
    # Check if the salt was given:
    if salt is None:
        salt = os.urandom(SALT_SIZE)

    # Create a key derivation function (PBKDF2) with SHA-256 as the hash function:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,  # Length of the key in bytes
        salt=salt,
        iterations=iterations,  # Number of iterations (higher is more secure but slower)
        backend=default_backend()
    )
    # Derive the encryption key from the provided password and salt (encoding with utf-8):
    key_bytes = kdf.derive(password.encode())
    return Key(key_bytes, password, salt)


@contextmanager
def database(db_path: str) -> tuple[sqlite3.Connection, sqlite3.Cursor]:
    # Create connection and cursor:
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    try:
        # Initialize keys table if one wasn't created already:
        connection.execute('''
            CREATE TABLE IF NOT EXISTS keys 
            (name TEXT PRIMARY KEY NOT NULL, key BLOB NOT NULL, password TEXT NOT NULL, salt BLOB NOT NULL);
        ''')
        connection.commit()

        # Return the connection and cursor:
        yield connection, cursor
    finally:
        # Close connection and cursor:
        cursor.close()
        connection.close()


@keys_app.command("create")
def create_key(
        key_name: Annotated[str, typer.Argument(case_sensitive=False, help="The name of the key. Not case-sensitive", show_default=False)],
        key_length: Annotated[int, typer.Option(min=8, clamp=True, help="The length of the key in bytes", show_default=False)] = 32,
        iterations: Annotated[int, typer.Option(min=1, clamp=True, help="Number of iteration to create the encryption key (a larger number is more secure but slower)", show_default=False)] = 10_000,
        override: Annotated[bool, typer.Option(help="Override an existing key if one is found")] = False
):
    """
    Creates a new key in the program's database. The name of the key is not case-sensitive.
    """
    connection: sqlite3.Connection
    cursor: sqlite3.Cursor
    with database(KEYS_DB_PATH) as (connection, cursor):
        # Convert the key name to lowercase:
        key_name = key_name.lower()

        # Search for it in the database (skip if override is true):
        if not override:
            cursor.execute("SELECT COUNT(*) FROM keys WHERE name = ?;", (key_name,))

            # If it already exists, prompt the user to confirm the override:
            if cursor.fetchone()[0] > 0:
                override = Confirm.ask("A similar key was found. Do you want to override it?")
                if not override:
                    raise typer.Abort()

        # Ask for password:
        password = Prompt.ask("Enter key password: ", password=True)

        # Derive the key:
        key = derive_key(password, key_length=key_length, iterations=iterations)

        # Save in the database:
        cursor.execute(
            'INSERT OR REPLACE INTO keys (name, key, password, salt) VALUES (?, ?, ?, ?);',
            (key_name, key.bytes, key.password, key.salt)
        )
        connection.commit()
        print("Key Created!")


@keys_app.command("delete")
def delete_key(
        key_name: Annotated[str, typer.Argument(case_sensitive=False, help="The name of the key. Not case sensitive")]
):
    """
    Deletes a key from the program's database. The name of the key is not case-sensitive.
    """
    # TODO: Delete key from the database
    pass


@keys_app.command()
def delete_all():
    """
    Deletes all keys from the program's database.
    """
    # TODO: Delete all keys and prompt
    pass


@keys_app.command("show")
def show_key(
    key_name: Annotated[Optional[str], typer.Argument(help="Name of the key to show. If not given, all keys will be shown")] = None,
    verbose: Annotated[bool, typer.Option(help="Show the key's full information")] = False
):
    """
    Show a specific key saved in the program, or all of them if one is not specified.
    """
    # TODO: Show a specific key/all keys using rich
    pass
