import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Encryptor:
    __slots__ = ['__key', '__salt']

    def __init__(self, password: str, salt_size: int):
        # Generate random salt bytes for the encryption:
        self.__salt = os.urandom(salt_size)
        # Derive key:
        self.__key = Encryptor.__derive_key(password, self.__salt)

    @staticmethod
    def __derive_key(password: str, salt: bytes) -> bytes:
        """
        Creates an encryption key based on the given password and salt parameters.
        :param password: A password chosen by the encryptor, will be used to determine the value of the encryption key.
        :type password: str
        :param salt: A random collection of bytes that will be added to the creation of the key to make it more secure.
        :type salt: bytes
        :return: The encryption key that was generated with the password and salt parameters.
        :rtype: bytes
        """
        # Create a key derivation function (PBKDF2) with SHA-256 as the hash function:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key length
            salt=salt,
            iterations=100000,  # Number of iterations (higher is more secure but slower)
            backend=default_backend()
        )
        # Derive the encryption key from the provided password and salt
        return kdf.derive(password.encode('utf-8'))
