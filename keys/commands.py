import keys
import typer
import sqlite3
from enum import Enum
from typing import Optional
from rich.table import Table
from rich import print as rich_print
from contextlib import contextmanager
import keys.database as keys_database
from rich.prompt import Confirm, Prompt
from typing_extensions import Annotated

# The part of the app responsible for keys handling:
keys_app = typer.Typer()

# Path to the keys' database:
KEYS_DB_PATH = "../keys.db"


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


def validate_key_password(key: keys.Key) -> None:
    """
    A simple function that asks the user for a key's password to make sure they are the owner of that
    key.
    :param key: The key whose password is requested.
    :raises typer.Abort: If the user provides a wrong password.
    """
    user_password = Prompt.ask("Please write the key's password", password=True)
    if user_password != key.password:
        rich_print("[bold red]Wrong password[/bold red]")
        raise typer.Abort()
    rich_print("[bright_green]Correct![/bright_green]")


class KeyLength(Enum):
    """
    An enum whose purpose is to present key length options when creating a key
    """
    SHORT = "SHORT"  # 16 bytes, 128 bits
    MEDIUM = "MEDIUM"  # 24 bytes, 192 bits
    LONG = "LONG"  # 32 bytes, 256 bits
    HUGE = "HUGE"  # 64 bytes, 512 bits

    def bytes(self) -> int:
        if self == KeyLength.SHORT:
            return 16
        elif self == KeyLength.MEDIUM:
            return 24
        elif self == KeyLength.LONG:
            return 32
        elif self == KeyLength.HUGE:
            return 64
        else:
            return 0

    @staticmethod
    def help_msg():
        return f"""
            The length of the encryption key, in bytes.
            {KeyLength.SHORT.name} - {KeyLength.SHORT.bytes()} bytes.
            {KeyLength.MEDIUM.name} - {KeyLength.MEDIUM.bytes()} bytes.
            {KeyLength.LONG.name} - {KeyLength.LONG.bytes()} bytes.
            {KeyLength.HUGE.name} - {KeyLength.HUGE.bytes()} bytes.
            """
    

@keys_app.command("create")
def create_key(
        key_name: Annotated[str, typer.Argument(case_sensitive=False, help="The name of the key. Not case-sensitive", show_default=False)],
        key_length: Annotated[KeyLength, typer.Option(case_sensitive=False, help=KeyLength.help_msg())] = KeyLength.LONG,
        iterations: Annotated[int, typer.Option(min=1, clamp=True, help="Number of iteration to create the encryption key (a larger number is more secure but slower)", show_default=False)] = 10_000,
        override: Annotated[bool, typer.Option(help="Override an existing key if one is found")] = False
):
    """
    Creates a new key in the program's database. The name of the key is not case-sensitive.
    """
    # Check if there is a key with a similar name:
    if not override:
        similar_key = keys_database.get_key(key_name)
        if similar_key is not None:
            override = Confirm.ask("A similar key was found. Do you want to override it?")
            if not override:
                raise typer.Abort()

    # Ask for password:
    password = Prompt.ask("Enter key password", password=True)

    # Create the key and add it to the database:
    keys_database.add_key(key_name, password, key_length.bytes(), iterations)

    rich_print("[bright_green]Key Created![/bright_green]")


@keys_app.command("delete")
def delete_key(
        key_name: Annotated[str, typer.Argument(case_sensitive=False, help="The name of the key. Not case sensitive")]
):
    """
    Deletes a key from the program's database. The name of the key is not case-sensitive.
    """
    # Search for the key in the database:
    key = keys_database.get_key(key_name)
    if key is None:
        rich_print(f"[red]The key '{key_name.lower()}' was not found in the database.[/red]")
        raise typer.Exit()

    # Check that the owner of the key is deleting it:
    validate_key_password(key)

    # Confirm that the user wants to do it:
    confirm = Confirm.ask(
        "Are you sure you want to delete this key? [bold bright_red]This action is irreversible![/bold bright_red]"
    )

    if confirm:
        # Delete the key:
        keys_database.remove_key(key_name)
        rich_print("[bright_green]Successfully deleted key[/bright_green]")
    else:
        raise typer.Abort()


def show_all_keys():
    # Create the table:
    keys_table = Table("Key Name")

    # Get all the keys from the database:
    with database(KEYS_DB_PATH) as (connection, cursor):
        cursor.execute('SELECT name FROM keys;')
        keys_names: list[tuple[str]] = cursor.fetchall()

        # Make sure there are keys
        if len(keys_names) == 0:
            rich_print("[red]No keys were found in the database.[/red]")
            raise typer.Exit()

    # Enter key names to table:
    for key_name in keys_names:
        keys_table.add_row(key_name[0])

    # Print Table:
    rich_print(keys_table)


@keys_app.command("show")
def show_key(
    key_name: Annotated[Optional[str], typer.Argument(
        help="""Name of the key to show. Pay attention that if a specific key was selected, the user will have to \
provide the key's password as well (since sensitive information about the key will be shown). If not specified, only \
the keys' names will be shown.""",
        show_default=False
    )] = None,
):
    """
    Shows a specific key saved in the program, or all of them if one is not specified.

    """
    # Check if we need to show all keys or just one:
    show_all = key_name is None
    if show_all:
        show_all_keys()
        raise typer.Exit()

    # Get the key:
    key = keys_database.get_key(key_name)

    # If the key was not found:
    if key is None:
        rich_print(f"[red]The key '{key_name.lower()}' was not found in the database.[/red]")
        raise typer.Exit()

    # Confirm they know the password:
    validate_key_password(key)

    # Create the table and print it:
    keys_table = Table("Key Name", "Password", "Salt", "Bytes")
    keys_table.add_row(key.name, key.password, key.salt.hex(), key.bytes.hex())
    rich_print(keys_table)
