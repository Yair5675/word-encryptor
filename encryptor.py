import os
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


############################################
# Exceptions related to the Encryptor class:
############################################
class DataAlreadyEncryptedException(Exception):
    """
    An exception for cases where the Encryptor is attempting to perform an action that requires the data to be non-encrypted,
    after it had been encrypted.
    """
    def __init__(self, message='Attempting to perform an action that requires the data to be non-encrypted'):
        super().__init__(message)


class DataNotLoadedException(Exception):
    """
    An exception for cases where the Encryptor is attempting to use the data saved in it for various purposes, but no data
    was loaded to it in the first place.
    """
    def __init__(self, message='Attempting to perform and action with data that was not yet loaded or was cleared'):
        super().__init__(message)


class DataNotEncryptedException(Exception):
    """
    An exception for cases where the Encryptor is attempting to perform an action that requires the data to be encrypted,
    while the data is not encrypted.
    """
    def __init__(self, message='Attempting to perform an action that requires the data to be encrypted'):
        super().__init__(message)


class InvalidEncryptedFileExtensionException(Exception):
    """
    An exception for cases where the Encryptor is trying to save the encrypted data into a file with invalid extension or an
    extension that differs from the guidelines of the Encryptor.
    """
    def __init__(self, message):
        super().__init__(message)


###################
# The class itself:
###################
class Encryptor:
    """
    A class that is used to encrypt data using a password-based key and various encryption methods.
    """
    __slots__ = [
        '__key',  # The key which will primarily decide how the data will be encrypted. It is based on the password given
                  # inside the constructor.
        '__salt',  # A random collection of bytes to improve the security of the encryption. The number of random bytes will
                   # be given as a parameter for the constructor.
        '__data',  # The data that was encrypted or is about to be encrypted by the Encryptor instance.
        '__is_encrypted'  # A boolean value which is True if the data held by the Encryptor instance is encrypted, and False
                          # otherwise.
        ]

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

    def is_empty(self) -> bool:
        """
        Checks if there is any data saved inside the Encryptor instance.
        :return: True if no data is saved inside the Encryptor instance, False otherwise.
        :rtype: bool
        """
        return len(self.__data) == 0

    def get_encrypted_data(self) -> bytes:
        """
        A getter method for the data that the Encryptor instance is holding. If the data hadn't been encrypted prior to the
        function call, it will be automatically encrypted and then returned. If no data was loaded into the instance, an
        exception will be raised.
        :return: The encrypted data saved inside the Encryptor instance.
        :rtype: bytes
        :raises DataNotLoadedException: If no data was saved in the instance or if it was cleared prior to the function call.
        """
        # Checking there is any data to return:
        if self.is_empty():
            raise DataNotLoadedException('Cannot retrieve encrypted data which was cleared or not loaded at all')
        # Making sure the data is encrypted before we return it:
        if not self.__is_encrypted:
            self.encrypt_data()

        return self.__data

    def is_encrypted(self) -> bool:
        """
        Checks if the data saved inside the Encryptor instance is already encrypted.
        :return: True if the data saved in the Encryptor instance is already encrypted, False otherwise. If no data is
                 present in the instance, False will be returned.
        :rtype: bool
        """
        return self.__is_encrypted

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
            raise DataAlreadyEncryptedException('Cannot change the pure data in the Encryptor as it was already encrypted')
        else:
            # If not, add the data:
            self.__data += data

    def encrypt_data(self):
        """
        Encrypts the data that was loaded to the Encryptor instance. Pay attention that the function does not return the
        encrypted data, but only performs the encryption. If the data in the encryptor is already encrypted, or no data was
        loaded at all, the function will raise an appropriate error.
        :raises DataAlreadyEncryptedException: If the current data in the Encryptor instance was already encrypted.
        :raises DataNotLoadedException: If no data was given to the Encryptor instance prior to the function's call, or if it
                                        was cleared.
        """
        # Checking if there is any data to encrypt:
        if self.is_empty():
            raise DataNotLoadedException('Cannot encrypt data which was cleared or not loaded at all')
        # Checking if the data was already encrypted:
        elif self.__is_encrypted:
            raise DataAlreadyEncryptedException('Cannot re-encrypt data after it was encrypted')

        # Padding the data to match the block size of the AES algorithm:
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(self.__data) + padder.finalize()

        # Generate a random IV (Initialization Vector) for the encryption:
        iv = os.urandom(16)

        # Create a Cipher object using AES in CFB mode with the key and IV:
        cipher = Cipher(algorithms.AES(self.__key), modes.CFB(iv), backend=default_backend())

        # Get an encryptor to perform the encryption:
        encryptor = cipher.encryptor()

        # Perform the encryption on the padded data:
        cipher_data = encryptor.update(padded_data) + encryptor.finalize()

        # Save the encrypted data as a concatenation of salt, IV and cipher_data:
        self.__data = self.__salt + iv + cipher_data

        # Change 'is_encrypted' to true:
        self.__is_encrypted = True

    def save_to_file(self, file_path: str):
        """
        Writes the encrypted data into a binary file (ends with '.bin'). If the file path doesn't end with '.bin', an
        exception will be raised. If no data was saved in the Encryptor instance, an exception will be raised. If the data
        wasn't encrypted prior to the function call, an exception will be raised.
        :param file_path: The relative or absolute path to the location where the encrypted data will be saved, ending in the
                          file's name and the '.bin' file extension.
        :raises DataNotLoadedException: If no data is saved in the instance.
        :raises DataNotEncryptedException: If the data saved in the instance was not encrypted prior to the function call.
        :raises InvalidEncryptedFileExtensionException: If the file to which the data will be written to doesn't end with the
                                                        '.bin' file extension.
        """
        # Checking there is data to write to a file:
        if self.is_empty():
            raise DataNotLoadedException('Cannot save encrypted data to file because data was cleared or not loaded at all')
        # Checking if the data wasn't encrypted:
        elif not self.__is_encrypted:
            raise DataNotEncryptedException('Data must be encrypted before being saved to a file')
        # Checking that the file path ends with the '.bin' extension:
        elif not file_path.endswith('.bin'):
            raise InvalidEncryptedFileExtensionException("Can only save encrypted data to files ending with '.bin'")

        # Saving the data to the specified file:
        with open(file_path, 'wb') as file:
            file.write(self.__data)

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
