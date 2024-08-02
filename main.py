import typer

# Creating the app:
app = typer.Typer(
    no_args_is_help=True,  # Activate help screen if no command is specified
)

if __name__ == '__main__':
    app()
