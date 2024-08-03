import typer
from keys import keys_app

# Creating the app:
app = typer.Typer(
    no_args_is_help=True,  # Activate help screen if no command is specified
)

# Add the keys' app:
app.add_typer(keys_app, name='keys', no_args_is_help=True)

# TODO:
#  1) Encrypt text (straight from terminal) with an option to save to a file.
#  2) Encrypt a file (either create a new encrypted copy or encrypt inplace).
#  3) Decrypt text (straight from terminal) with an option to save to a file.
#  4) Decrypt a file (NOT inplace, always create copy).
#  5) Add a key management system


if __name__ == '__main__':
    app()
