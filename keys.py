import os
import typer
from typing import Optional
from collections import namedtuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# The part of the app responsible for keys handling:
keys_app = typer.Typer()

# A key datatype that will save all necessary information:
Key = namedtuple("Key", ["bytes", "password", "salt"])

# The salt size used in Key generation (in bytes):
SALT_SIZE = 32

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
