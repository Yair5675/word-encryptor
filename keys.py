import os
import typer
import sqlite3
from typing import Optional
from rich.table import Table
from collections import namedtuple
from rich import print as rich_print
from contextlib import contextmanager
from rich.prompt import Confirm, Prompt
from typing_extensions import Annotated
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# The part of the app responsible for keys handling:
keys_app = typer.Typer()

# A key datatype that will save all necessary information:
Key = namedtuple("Key", ["name", "bytes", "password", "salt"])

# The salt size used in Key generation (in bytes):
SALT_SIZE = 32

# Path to the keys' database:
KEYS_DB_PATH = "keys.db"


def derive_key(password: str, key_name: Optional[str] = None, salt: Optional[bytes] = None, key_length: int = 32, iterations: int = 10_000) -> Key:
    """
    Creates an encryption key based on the given password and salt parameters.
    :param password: A password chosen by the encryptor, will be used to determine the value of the encryption key.
    :param key_name: An optional name to the key. If not specified, the name will be an empty string.
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
    return Key("" if key_name is None else key_name, key_bytes, password, salt)


@contextmanager
def database(db_path: str) -> tuple[sqlite3.Connection, sqlite3.Cursor]:
    # Create connection and cursor:
    connection = sqlite3.connect(db_path)
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
    with database(KEYS_DB_PATH) as (connection, cursor):
        # Fetch the data:
        cursor.execute('SELECT name, bytes, password, salt FROM keys WHERE name = ?', (key_name.lower(),))
        key_data = cursor.fetchone()

        # Check if the key was found:
        if len(key_data) > 0:
            return Key(*key_data[0])
    return None


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
        password = Prompt.ask("Enter key password", password=True)

        # Derive the key:
        key = derive_key(password, key_length=key_length, iterations=iterations)

        # Save in the database:
        cursor.execute(
            'INSERT OR REPLACE INTO keys (name, bytes, password, salt) VALUES (?, ?, ?, ?);',
            (key_name, key.bytes, key.password, key.salt)
        )
        connection.commit()
        rich_print("[bright_green]Key Created![/bright_green]")


@keys_app.command("delete")
def delete_key(
        key_name: Annotated[str, typer.Argument(case_sensitive=False, help="The name of the key. Not case sensitive")]
):
    """
    Deletes a key from the program's database. The name of the key is not case-sensitive.
    """
    connection: sqlite3.Connection
    cursor: sqlite3.Cursor
    with database(KEYS_DB_PATH) as (connection, cursor):
        # Search for the key in the database:
        key = get_key(key_name)
        if key is None:
            rich_print(f"[red]The key '{key_name.lower()}' was not found in the database.[/red]")
            raise typer.Exit()

        # Confirm that the user wants to do it:
        confirm = Confirm.ask("Are you sure you want to delete this key? [bold bright_red]This action is irreversible![/bold bright_red]")

        if confirm:
            # Delete the key:
            cursor.execute("DELETE FROM keys WHERE name = ?", (key_name.lower(),))
            connection.commit()
            rich_print("[bright_green]Successfully deleted key[/bright_green]")
        else:
            raise typer.Abort()


@keys_app.command()
def delete_all():
    """
    Deletes all keys from the program's database.
    """
    connection: sqlite3.Connection
    cursor: sqlite3.Cursor
    with database(KEYS_DB_PATH) as (connection, cursor):
        # Make sure there are keys in the database:
        cursor.execute('SELECT COUNT(*) FROM keys')
        if cursor.fetchone()[0] == 0:
            rich_print("[red]No keys were found in the database.[/red]")
            raise typer.Exit()

        # Ask the user if they're sure:
        confirm = Confirm.ask("Are you sure you want to delete EVERY key? [bold bright_red]This action is irreversible![/bold bright_red]")

        if confirm:
            # Delete all keys:
            cursor.execute("DELETE FROM keys")
            connection.commit()
            rich_print("[bright_green]Successfully deleted every key[/bright_green]")
        else:
            raise typer.Abort()


@keys_app.command("show")
def show_key(
    key_name: Annotated[Optional[str], typer.Argument(help="Name of the key to show. If not given, all keys will be shown")] = None,
    verbose: Annotated[bool, typer.Option(help="Show the key's full information")] = False
):
    """
    Shows a specific key saved in the program, or all of them if one is not specified.
    """
    # Check if we need to show all keys or just one:
    show_all = key_name is None

    # Create a table based on the verbose:
    if verbose:
        keys_table = Table("Key Name", "Password", "Salt", "Bytes")
    else:
        keys_table = Table("Key Name")

    connection: sqlite3.Connection
    cursor: sqlite3.Cursor
    with database(KEYS_DB_PATH) as (connection, cursor):
        # Get keys data and add them to the table:
        details_to_get = 'name, password, salt, bytes' if verbose else 'name'
        if show_all:
            cursor.execute(f'SELECT {details_to_get} FROM keys;')
        else:
            cursor.execute(f'SELECT {details_to_get} FROM keys WHERE name = ?', (key_name.lower(),))
        keys_data = cursor.fetchall()

        # Check that keys are stored:
        if len(keys_data) == 0:
            if show_all:
                rich_print("[red]No keys were found in the database.[/red]")
            else:
                rich_print(f"[red]The key '{key_name.lower()}' was not found in the database.[/red]")
            raise typer.Exit()

    # Add to table:
    for key in keys_data:
        if verbose:
            # Order is name, password, salt, bytes (show salt and bytes with shorter hex code):
            keys_table.add_row(key[0], key[1], key[2].hex(), key[3].hex())
        else:
            keys_table.add_row(key[0])
    rich_print(keys_table)
