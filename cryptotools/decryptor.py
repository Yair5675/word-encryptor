import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptotools.encryptor import Encryptor, InvalidEncryptedFileExtensionException


############################################
# Exceptions related to the Decryptor class:
############################################
class DecryptorException(Exception):
    """
    Base class for all exceptions that are raised due to misuse of the Decryptor class.
    """
    def __init__(self, message):
        super().__init__(message)


class DataAlreadyDecryptedException(DecryptorException):
    """
    An exception for cases where the Decryptor instance is trying to perform an action that requires the data to not be
    decrypted, while it had already been decrypted.
    """
    pass


class DataNotDecryptedException(DecryptorException):
    """
    An exception for cases where the Decryptor instance is trying to perform an action that requires decrypted data, while
    no decrypted data is saved in the instance.
    """
    pass


###################
# The class itself:
###################
class Decryptor:
    """
    A class that is used to decrypt encrypted data using a password-based key. The class is meant to decrypt data which was
    encrypted using the Encryptor class, therefor it is not for general purpose decryption.
    """
    __slots__ = [
        '__password',  # The password used during the encryption. It is needed to reverse the process.

        '__decrypted_data'  # When using the Decryptor instance to decrypt data, the decrypted data will be saved to this
                            # attribute.
    ]

    def __init__(self, password: str):
        """
        The constructor of the Decryptor class.
        :param password: A piece of string that was used in the encryption process to derive an encryption key. It will be
                         used in the decryption process as well.
        :type password: str
        :rtype: Decryptor
        """
        # Setting the password:
        self.set_password(password)
        # Setting the decrypted data to an empty bytes object:
        self.__decrypted_data = b''

    def set_password(self, password: str):
        """
        A setter method for the password inside the Decryptor class.
        :param password: A piece of string that was used in the encryption process to derive an encryption key. It will be
                         used in the decryption process as well.
        :type password: str
        """
        # Ensuring type safety for the password:
        if type(password) != str:
            raise TypeError(f'Expected a password of type str, got {type(password)} instead')
        self.__password = password

    def is_decrypted(self) -> bool:
        """
        Checks if the Decryptor instance is holding data it had already decrypted, or if it's empty.
        :return: True if the Decryptor instance holds decrypted data in it, False otherwise.
        :rtype: bool
        """
        return len(self.__decrypted_data) != 0

    def decrypt_data(self, encrypted_data: str | bytes):
        """
        Receives input in the form of bytes or str, and decrypts it. The decrypted result is not returned but saved inside
        the Decryptor instance.
        :param encrypted_data: The encrypted input which will be decrypted and saved in the instance.
        :type encrypted_data: str | bytes
        :return: The current Decryptor instance to support the builder pattern.
        :rtype: Decryptor
        """
        # Ensuring the type of 'encrypted_data' is indeed bytes:
        if type(encrypted_data) != bytes and type(encrypted_data) != str:
            raise TypeError(f"Expected encrypted data of type bytes or str, got {type(encrypted_data)} instead")

        # Checking the decryptor doesn't hold any data:
        if self.is_decrypted():
            raise DataAlreadyDecryptedException("Cannot decrypt new data until the existing decrypted data is cleared")

        # Changing the encrypted data to bytes if it wasn't already:
        if type(encrypted_data) != bytes:
            encrypted_data = bytes(encrypted_data)

        # Extract salt, IV, and ciphertext from the encrypted data
        salt = encrypted_data[:Encryptor.SALT_SIZE]
        iv = encrypted_data[Encryptor.SALT_SIZE:Encryptor.SALT_SIZE + Encryptor.IV_SIZE]
        cipher_data = encrypted_data[Encryptor.SALT_SIZE + Encryptor.IV_SIZE:]

        # Deriving the key from the password and salt:
        key = Encryptor.derive_key(self.__password, salt)

        # Creating a Cipher object using AES in CFB mode with the key and IV:
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

        # Getting a decryptor to perform the decryption:
        decryptor = cipher.decryptor()

        # Performing the decryption on the ciphertext:
        padded_data = decryptor.update(cipher_data) + decryptor.finalize()

        # Removing padding:
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        # Saving the data inside the 'decrypted_data' attribute:
        self.__decrypted_data = data

        # Returning the current Decryptor object to support the builder pattern:
        return self

    def get_decrypted_data(self) -> bytes:
        """
        A method for getting the decrypted data AFTER the decryption process.
        :return: The decrypted data that is saved inside the instance.
        :rtype: bytes
        """
        if not self.is_decrypted():
            raise DataNotDecryptedException("No decrypted data is saved inside the instance")
        return self.__decrypted_data

    def decrypt_from_file(self, path: str) -> bytes:
        """
        Receives a path to an encrypted binary file, decrypts the content of the file and saves the decrypted data inside
        the Decryptor instance.
        :param path: The absolute path to the encrypted binary file. The path MUST be absolute, and the file MUST end in the
                     extension '.bin'.
        :type path: str
        :returns: The decrypted version of the data in the specified file.
        :rtype: bytes
        """
        # Check the path:
        if type(path) != str:
            raise TypeError(f"Expected path of type str, got {type(path)} instead")
        if not os.path.isabs(path):
            raise ValueError(f'The function only accepts absolute paths, yet a relative path was given ({path})')
        if not os.path.exists(path):
            raise IOError("The given path to a binary file doesn't exist")
        if not os.path.isfile(path):
            raise ValueError(f'The function only decrypts binary files (to encrypt a directory, see "decrypt_from_files")')
        if not path.endswith('.bin'):
            raise InvalidEncryptedFileExtensionException("Can only decrypt files ending with '.bin'")

        # Reading the binary data:
        with open(path, 'rb') as file:
            data = file.read()
            # Encrypting the data and returning it:
            return self.decrypt_data(data).get_decrypted_data()
