from cryptotools.encryptor import Encryptor
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


############################################
# Exceptions related to the Decryptor class:
############################################
class DecryptorException(Exception):
    """
    Base class for all exceptions that are raised due to misuse of the Decryptor class.
    """
    def __init__(self, message):
        super().__init__(message)


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

    def decrypt_data(self, encrypted_data: bytes) -> None:
        # TODO: Add documentation to the function
        # TODO: Raise an error if previous data was already decrypted and not cleared

        # Ensuring the type of 'encrypted_data' is indeed bytes:
        if type(encrypted_data) != bytes:
            raise TypeError(f"Expected encrypted data of type bytes, got {type(encrypted_data)} instead")

        # Extract salt, IV, and ciphertext from the encrypted data
        salt = encrypted_data[:Encryptor.SALT_SIZE]
        iv = encrypted_data[Encryptor.SALT_SIZE:Encryptor.IV_SIZE]
        cipher_data = encrypted_data[Encryptor.IV_SIZE:]

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
