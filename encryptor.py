import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class DataAlreadyEncryptedException(Exception):
    """
    An exception for cases where new data is being added to the encryptor's data, after the old data was encrypted.
    """
    def __init__(self):
        super().__init__('Attempt to add new data to already encrypted data')


class DataNotLoadedException(Exception):
    """
    An exception for cases where the encryptor is attempting to encrypt data, but none is loaded.
    """
    def __init__(self):
        super().__init__('Cannot encrypt data that was not yet loaded')


class Encryptor:
    __slots__ = ['__key', '__salt', '__data', '__is_encrypted']

    def __init__(self, password: str, salt_size: int):
        # Ensuring type safety for the password:
        if type(password) != str:
            raise TypeError(f'Expected a password of type str, got {type(password)} instead')
        # Ensuring the salt size is a valid UNSIGNED integer:
        if type(salt_size) != int:
            raise TypeError(f'Expected an unsigned integer as salt size, got {type(salt_size)} instead')
        elif salt_size <= 0:
            raise ValueError(f'Invalid value for salt size: {salt_size} (should be above 0)')

        # Generate random salt bytes for the encryption:
        self.__salt = os.urandom(salt_size)
        # Derive key:
        self.__key = Encryptor.__derive_key(password, self.__salt)
        # Initializing the saved data and the 'is_encrypted' attribute:
        self.clear_data()

    def clear_data(self):
        """
        Clears the text saved in the instance.
        """
        self.__data = ''
        self.__is_encrypted = False

    def enter_data(self, data: str):
        """
        Enters new data to the encryptor. If the data stored in the encryptor is already encrypted, an error will be raised.
        :param data: A new string of data that will be saved in the instance and be encrypted in the future using the
                     'encrypt' function.
        :raises DataAlreadyEncryptedException: If the current Encryptor instance has not cleared its data since it was last
                                               encrypted.
        """
        # Checking if the data was already encrypted:
        if self.__is_encrypted:
            raise DataAlreadyEncryptedException()
        else:
            # If not, add the data:
            self.__data += data

    def encrypt_data(self):
        """
        Encrypts the data that was loaded to the Encryptor instance. Pay attention that the function does not return the
        encrypted data, but only performs the encryption. If the data in the encryptor is already encrypted, or no data was
        loaded at all, the function will raise an appropriate error.
        """
        pass

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
