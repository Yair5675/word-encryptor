import os
from collections import deque
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


############################################
# Exceptions related to the Encryptor class:
############################################
class EncryptorException(Exception):
    """
    Base exception for all custom exceptions that arise from mishandling the Encryptor class.
    """
    def __init__(self, message):
        super().__init__(message)


class DataAlreadyEncryptedException(EncryptorException):
    """
    An exception for cases where the Encryptor is attempting to perform an action that requires the data to be non-encrypted,
    after it had been encrypted.
    """
    def __init__(self, message='Attempting to perform an action that requires the data to be non-encrypted'):
        super().__init__(message)


class DataNotLoadedException(EncryptorException):
    """
    An exception for cases where the Encryptor is attempting to use the data saved in it for various purposes, but no data
    was loaded to it in the first place.
    """
    def __init__(self, message='Attempting to perform and action with data that was not yet loaded or was cleared'):
        super().__init__(message)


class DataNotEncryptedException(EncryptorException):
    """
    An exception for cases where the Encryptor is attempting to perform an action that requires the data to be encrypted,
    while the data is not encrypted.
    """
    def __init__(self, message='Attempting to perform an action that requires the data to be encrypted'):
        super().__init__(message)


class InvalidEncryptedFileExtensionException(EncryptorException):
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
    This class supports the builder pattern when handling the data its instances contain, so chaining multiple commands
    together is available to the user of the class.
    """
    __slots__ = [
        '__key',  # The key which will primarily decide how the data will be encrypted. It is based on the password given
                  # inside the constructor.

        '__salt',  # A random collection of bytes to improve the security of the encryption.

        '__raw_data',  # A deque where each element is a collection of non-encrypted bytes that the user fed the instance.
                       # The size of each element will be limited in a way that the size of the encryption of the bytes in
                       # the element will always be less than or equal to the 'max_encryption_size' (see also).

        '__encrypted_data',  # A bytes object whose size is equal to the 'max_encryption_size' attribute (see also). This is
                             # done as a safety mechanism to prevent oversize encryptions.

        '__is_encrypted',  # A boolean value which is True if the current data chunk is encrypted, and False otherwise.

        '__max_chunk_size'  # To prevent excessive memory usages, this attribute will serve as an upper bound to the size of
                            # the raw data in each chunk. This size will ensure that encrypting a raw data chunk will always
                            # result in encrypted data whose size is less than the maximum size specified in the constructor.
        ]

    # Constants in the class:
    MINIMUM_ENCRYPTION_SIZE = 1024 * 1024  # The minimum amount of bytes that is allocated to the encryption.

    __IV_SIZE = 16  # The amount of bytes that will be dedicated to the initialization vector during the encryption.
    __SALT_SIZE = 32  # The amount of bytes that will be dedicated to the salt

    __KEY_LENGTH = 32  # The amount of bytes the key will be made of (multiply by 8 to get the amount of bits)
    __KEY_ITERATIONS = 100000  # Number of iteration to create the encryption key (higher is more secure but slower)

    def __init__(self, password: str, max_encryption_size: int = MINIMUM_ENCRYPTION_SIZE):
        """
        The constructor of the encryptor class.
        :param password: A piece of string that will be used to make a specialized key for the encryption method.
        :type password: str
        :param max_encryption_size: An upper bound to the size of the encrypted data, measured in bytes, used to prevent
                                    overly large encryption data and excessive memory usage. This value must be above or
                                    equal to the class attribute MINIMUM_ENCRYPTION_SIZE (the default size), but can be
                                    larger if specified.
        :type max_encryption_size: int
        """
        # Ensuring type safety for the password:
        if type(password) != str:
            raise TypeError(f'Expected a password of type str, got {type(password)} instead')

        # Ensuring type safety for the max encryption size:
        if type(max_encryption_size) != int:
            raise TypeError(f'Expected a max encryption size of type int, got {type(max_encryption_size)} instead')
        # Ensuring the value of the max encryption size is valid:
        if max_encryption_size < Encryptor.MINIMUM_ENCRYPTION_SIZE:
            raise ValueError(f'Max encryption size must be above or equal to '
                             f'{Encryptor.MINIMUM_ENCRYPTION_SIZE // (1024 * 1024)} MB ({Encryptor.MINIMUM_ENCRYPTION_SIZE}'
                             f' bytes)')
        # Calculating the max chunk size:
        self.__max_chunk_size = Encryptor.__calc_raw_data_size(max_encryption_size)

        # Generate random salt bytes for the encryption:
        self.__salt = os.urandom(Encryptor.__SALT_SIZE)
        # Derive key:
        self.__key = Encryptor.derive_key(password, self.__salt)

        # Initializing the encrypted data:
        self.__encrypted_data = b''
        # Initializing the raw data:
        self.__raw_data = deque()
        # Initializing the is_encrypted flag:
        self.__is_encrypted = False

    def is_empty(self) -> bool:
        """
        Checks if there is any data saved inside the Encryptor instance.
        :return: True if no data is saved inside the Encryptor instance, False otherwise.
        :rtype: bool
        """
        return not self.__raw_data

    def get_encrypted_data(self) -> bytes:
        """
        A getter method for the data that the Encryptor instance is holding. If the size of the saved data is larger than
        the maximum encryption size, only a chunk of the saved data will be encrypted and returned (the size of the chunk
        will be equal to the maximum encryption size).
        If the data hadn't been encrypted prior to the function call, it will be automatically encrypted and then returned.
        If no data was loaded into the instance, an exception will be raised.
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

        # Return the encrypted data of the current chunk (without removing it):
        return self.__encrypted_data

    def is_encrypted(self) -> bool:
        """
        Checks if the data saved inside the Encryptor instance is already encrypted.
        :returns: True if the data saved in the Encryptor instance is already encrypted, False otherwise. If no data is
                 present in the instance, False will be returned.
        :rtype: bool
        """
        return self.__is_encrypted

    def clear_chunk(self) -> bool:
        """
        Clears the first saved chunk in the encryptor (the first chunk will be the oldest chunk of data that was not cleared
        prior to the function call).
        :return: True if after the removal of the chunk the encryptor is empty, False otherwise.
        """
        # Getting the number of chunks saved:
        chunks_saved = len(self.__raw_data)

        # Removing the first chunk:
        if chunks_saved > 0:
            self.__raw_data.popleft()

        # Returning the state of the deque after the popping (empty or not):
        return chunks_saved <= 1

    def clear_data(self):
        """
        Clears the all data saved in the instance.
        :returns: The current Encryptor instance. This way chaining multiple different methods together is doable.
        :rtype: Encryptor
        """
        # Resetting the raw data:
        self.__raw_data.clear()

        # Resetting the encrypted data:
        self.__encrypted_data = b''

        # Resetting the is_encrypted flag:
        self.__is_encrypted = False

        # Returning the current Encryptor instance to support the builder pattern:
        return self

    def enter_data(self, data: str):
        """
        Enters new data to the encryptor. If the data stored in the encryptor is already encrypted, an error will be raised.
        If the data given is too large to be added to the last chunk of saved data, it will be split into smaller chunks that
        will be added to the encryptor. Notice the 'encrypt' method will only encrypt the first chunk that was entered.
        :param data: A new string of data that will be saved in the instance and be encrypted in the future using the
                     'encrypt' function.
        :returns: The current Encryptor instance. This way chaining multiple different methods together is doable.
        :rtype: Encryptor
        :raises DataAlreadyEncryptedException: If the current Encryptor instance has not cleared its data since it was last
                                               encrypted.
        """
        # Checking if the data was already encrypted:
        if self.__is_encrypted:
            raise DataAlreadyEncryptedException('Cannot change the pure data in the Encryptor as it was already encrypted')

        # Getting the last data chunk saved:
        last_chunk = self.__raw_data.pop() if self.__raw_data else b''  # Make sure to check the raw data isn't empty

        # Calculating the space left in the chunk:
        space_left = self.__max_chunk_size - len(last_chunk)

        # Adding what we can to the last chunk:
        if space_left > 0:
            last_chunk += data[:space_left].encode('utf-8')
            data = data[space_left:]

        # Returning the last chunk to the deque:
        self.__raw_data.append(last_chunk)

        # Adding the rest of the new data in chunks until nothing is left:
        while len(data) > 0:
            self.__raw_data.append(data[:self.__max_chunk_size].encode('utf-8'))
            data = data[self.__max_chunk_size:]

        # Returning the current Encryptor instance to support the builder pattern:
        return self

    def encrypt_data(self):
        """
        Encrypts the data that was loaded to the Encryptor instance. Pay attention that the function does not return the
        encrypted data, but only performs the encryption. If the data in the encryptor is already encrypted, or no data was
        loaded at all, the function will raise an appropriate error.
        :returns: The current Encryptor instance. This way chaining multiple different methods together is doable.
        :rtype: Encryptor
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
        padded_data = padder.update(self.__raw_data[0]) + padder.finalize()  # Encrypting only the first chunk of data

        # Generate a random IV (Initialization Vector) for the encryption:
        iv = os.urandom(Encryptor.__IV_SIZE)

        # Create a Cipher object using AES in CFB mode with the key and IV:
        cipher = Cipher(algorithms.AES(self.__key), modes.CFB(iv), backend=default_backend())

        # Get an encryptor to perform the encryption:
        encryptor = cipher.encryptor()

        # Perform the encryption on the padded data:
        cipher_data = encryptor.update(padded_data) + encryptor.finalize()

        # Save the encrypted data as a concatenation of salt, IV and cipher_data:
        self.__encrypted_data = self.__salt + iv + cipher_data

        # Change 'is_encrypted' to true:
        self.__is_encrypted = True

        # Returning the current Encryptor instance to support the builder pattern:
        return self

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
    def __calc_encrypted_data_size(raw_data_size: int) -> int:
        """
        Given the size of the raw data, the function calculates the future size of the encrypted data, with an added safety
        margin.
        :param raw_data_size: The size of the raw data (data before encryption).
        :return: The future size of the data after encryption.
        """
        # Adding a safety margin (just to be safe the prediction will be larger than the actual result):
        safety_margin = 64
        # Through experiments, the correlation between raw len and encrypted len is: encrypted = raw + 64
        return raw_data_size + 64 + safety_margin

    @staticmethod
    def __calc_raw_data_size(encrypted_data_size: int) -> int:
        """
        Given the size of the encrypted data, the function calculates the size of the raw data that was encrypted.
        :param encrypted_data_size: The number of bytes of the encrypted data.
        :type encrypted_data_size: int
        :return: The size of the original raw data that was encrypted, minus a safety margin.
        """
        # Adding a safety margin (just to ensure the prediction will be lower than the actual result):
        safety_margin = 64
        # Through experiments, the correlation between raw len and encrypted len is: encrypted = raw + 64.
        return encrypted_data_size - 64 - safety_margin

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
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
            length=Encryptor.__KEY_LENGTH,  # Length of the key in bytes
            salt=salt,
            iterations=Encryptor.__KEY_ITERATIONS,  # Number of iterations (higher is more secure but slower)
            backend=default_backend()
        )
        # Derive the encryption key from the provided password and salt
        return kdf.derive(password.encode('utf-8'))
