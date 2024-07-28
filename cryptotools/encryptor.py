import os
from typing import Union
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
    was loaded to it in the first place, or it was cleared.
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
    To deal with large amount of data, the class breaks down the data it receives into chunks. The maximum size of each chunk
    is determined in the constructor, where the user is asked to specify the maximum encryption size in bytes.
    If the data is too large and requires multiple chunks, calling the encrypt method will only encrypt the first chunk, and
    only this chunk will be available. To proceed to the next chunk, use the 'pop_chunk' method to remove the non-encrypted
    chunk (which will also be returned).
    """

    ######################
    # Instance attributes:
    ######################
    __slots__ = [
        '__key',  # The key which will primarily decide how the data will be encrypted. It is based on the password given
                  # inside the constructor.

        '__salt',  # A random collection of bytes to improve the security of the encryption.

        '__raw_data',  # A deque where each element is a collection of non-encrypted bytes that the user fed the instance.
                       # The size of each element will be limited in a way that the size of the encryption of the bytes in
                       # the element will always be less than or equal to the 'max_encryption_size' (see also).

        '__encrypted_data',  # A bytes object whose size is equal to the 'max_encryption_size' attribute (see also). This is
                             # done as a safety mechanism to prevent oversize encryptions.

        '__max_chunk_size'  # To prevent excessive memory usages, this attribute will serve as an upper bound to the size of
                            # the raw data in each chunk. This size will ensure that encrypting a raw data chunk will always
                            # result in encrypted data whose size is less than the maximum size specified in the constructor.
        ]

    #############
    # Constants:
    #############

    # The minimum amount of bytes that is allocated to the encryption:
    MINIMUM_ENCRYPTION_SIZE = 1024 * 1024

    # The amount of bytes that will be dedicated to the initialization vector during the encryption:
    IV_SIZE = 16

    # The name of an individual encrypted file when encrypting multiple chunks (brackets are placeholder
    # for chunk number):
    CHUNK_NAME = 'pt_{}.bin'

    # The amount of bytes that will be dedicated to the salt:
    SALT_SIZE = 32

    # The amount of bytes the key will be made of (multiply by 8 to get the amount of bits):
    __KEY_LENGTH = 32

    # Number of iteration to create the encryption key (higher is more secure but slower):
    __KEY_ITERATIONS = 100000

    def __init__(self, password: str, max_encryption_size: int = MINIMUM_ENCRYPTION_SIZE):
        """
        The constructor of the Encryptor class.
        :param password: A piece of string that will be used to make a specialized key for the encryption method.
        :type password: str
        :param max_encryption_size: An upper bound to the size of the encrypted data, measured in bytes, used to prevent
                                    overly large encryption data and excessive memory usage. This value must be above or
                                    equal to the class attribute MINIMUM_ENCRYPTION_SIZE (the default size), but can be
                                    larger if specified.
        :type max_encryption_size: int
        :rtype: Encryptor

        Code examples:
            >>> # Properly instantiating an Encryptor with default max encryption size:
            >>> encryptor = Encryptor('password123')
            >>> # Properly instantiating an Encryptor with a custom max encryption size:
            >>> encryptor = Encryptor('password123', max_encryption_size=3*1024*1024)  # 3*1024*1024 = 3145728 bytes = 3 MB

            >>> # Instantiating an object with an invalid password or max encryption size types:
            >>> encryptor = Encryptor(password=1234)  # Will result in TypeError
            >>> encryptor = Encryptor('password123', max_encryption_size='10002')  # Will result in TypeError

            >>> # Instantiating an object with an invalid value for the max encryption size:
            >>> encryptor = Encryptor('password123', max_encryption_size=-100)  # Will result in ValueError
            >>> encryptor = Encryptor('password123', max_encryption_size=Encryptor.MINIMUM_ENCRYPTION_SIZE - 1)  # Will result in ValueError
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
        self.__salt = os.urandom(Encryptor.SALT_SIZE)
        # Derive key:
        self.__key = Encryptor.derive_key(password, self.__salt)

        # Initializing the encrypted data:
        self.__encrypted_data = b''
        # Initializing the raw data:
        self.__raw_data = deque()

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
        :return: The encrypted data saved inside the Encryptor instance.
        :rtype: bytes
        :raises DataNotLoadedException: If no data was saved in the instance or if it was cleared prior to the function call.
        """
        # Checking there is any data to return:
        if self.is_empty():
            raise DataNotLoadedException('Cannot retrieve encrypted data which was cleared or not loaded at all')
        # Making sure the data is encrypted before we return it:
        if not self.is_encrypted():
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
        return len(self.__encrypted_data) != 0

    def pop_chunk(self) -> bytes:
        """
        Clears the first saved chunk in the encryptor (the first chunk will be the oldest chunk of data that was not cleared
        prior to the function call) and returns it.
        :return: The raw data chunk that was removed from the encryptor.
        :rtype: bytes
        :raises DataNotLoadedException: If the instance doesn't hold any data to be cleared.
        """
        # Getting the number of chunks saved:
        chunks_saved = len(self.__raw_data)

        # Checking if the deque is empty:
        if chunks_saved == 0:
            raise DataNotLoadedException('Cannot clear chunk from empty Encryptor instance')

        # Removing the encrypted data:
        self.__encrypted_data = b''

        # Removing the first chunk and returning it:
        return self.__raw_data.popleft()

    def clear_data(self):
        """
        Clears the all data saved in the instance.
        :returns: The current Encryptor instance. This way chaining multiple different methods together is doable.
        :rtype: Encryptor
        :raises DataNotLoadedException: If the encryptor was already cleared prior to the function call.
        """
        # Checking if the deque is empty:
        if self.is_empty():
            raise DataNotLoadedException('Cannot clear data from empty Encryptor instance')

        # Resetting the raw data:
        self.__raw_data.clear()

        # Resetting the encrypted data:
        self.__encrypted_data = b''

        # Returning the current Encryptor instance to support the builder pattern:
        return self

    def enter_data(self, data: Union[str, bytes]):
        """
        Enters new data to the encryptor. If the data stored in the encryptor is already encrypted, an error will be raised.
        If the data given is too large to be added to the last chunk of saved data, it will be split into smaller chunks that
        will be added to the encryptor. Notice the 'encrypt' method will only encrypt the first chunk that was entered.
        :param data: A new piece of data that will be saved in the instance and be encrypted in the future using the
                     'encrypt' function.
        :returns: The current Encryptor instance. This way chaining multiple different methods together is doable.
        :rtype: Encryptor
        :raises DataAlreadyEncryptedException: If the current Encryptor instance has not cleared its data since it was last
                                               encrypted.
        """
        # Checking the type of data:
        if not isinstance(data, (str, bytes)):
            raise TypeError(f'Expected data of type str or bytes, got {type(data)} instead')

        # Checking if the data was already encrypted:
        if self.is_encrypted():
            raise DataAlreadyEncryptedException('Cannot change the pure data in the Encryptor as it was already encrypted')

        # Converting the data to bytes if a string was given:
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Getting the last data chunk saved:
        last_chunk = self.__raw_data.pop() if self.__raw_data else b''  # Make sure to check the raw data isn't empty

        # Calculating the space left in the chunk:
        space_left = self.__max_chunk_size - len(last_chunk)

        # Adding what we can to the last chunk:
        if space_left > 0:
            last_chunk += data[:space_left]
            data = data[space_left:]

        # Returning the last chunk to the deque:
        self.__raw_data.append(last_chunk)

        # Adding the rest of the new data in chunks until nothing is left:
        while len(data) > 0:
            self.__raw_data.append(data[:self.__max_chunk_size])
            data = data[self.__max_chunk_size:]

        # Returning the current Encryptor instance to support the builder pattern:
        return self

    def encrypt_data(self):
        """
        Encrypts the data that was loaded to the Encryptor instance. The function only encrypts the first chunk saved in the
        encryptor (the oldest chunk that wasn't cleared). To encrypt the rest of the chunks, the current chunk will have to
        be cleared prior to calling this function again.
        Pay attention that the function does not return the encrypted data, but only performs the encryption. If the data in
        the encryptor is already encrypted, or no data was loaded at all, the function will raise an appropriate error.
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
        elif self.is_encrypted():
            raise DataAlreadyEncryptedException('Cannot re-encrypt data after it was encrypted')

        # Padding the data to match the block size of the AES algorithm:
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(self.__raw_data[0]) + padder.finalize()  # Encrypting only the first chunk of data

        # Generate a random IV (Initialization Vector) for the encryption:
        iv = os.urandom(Encryptor.IV_SIZE)

        # Create a Cipher object using AES in CFB mode with the key and IV:
        cipher = Cipher(algorithms.AES(self.__key), modes.CFB(iv), backend=default_backend())

        # Get an encryptor to perform the encryption:
        encryptor = cipher.encryptor()

        # Perform the encryption on the padded data:
        cipher_data = encryptor.update(padded_data) + encryptor.finalize()

        # Save the encrypted data as a concatenation of salt, IV and cipher_data:
        self.__encrypted_data = self.__salt + iv + cipher_data

        # Returning the current Encryptor instance to support the builder pattern:
        return self

    def save_to_file(self, file_path: str):
        """
        Writes the encrypted data into a binary file (ends with '.bin'). Pay attention only the first chunk of raw data will
        be encrypted, and not necessarily the entire saved data (for that, see 'save_to_files'). Pay attention that in
        contrast to the 'save_to_files' function, the current function does not delete any data saved in the instance, and
        the current encrypted chunk will still be saved in the instance after it is written to the specified path. The path
        of the file must be an ABSOLUTE path to the location where the chunk will be saved.
        :param file_path: The absolute path to the location where the encrypted data will be saved, ending in the file's name
                          and the '.bin' file extension.
        :raises ValueError: If the given path isn't an absolute path.
        :raises DataNotLoadedException: If no data is saved in the instance.
        :raises DataNotEncryptedException: If the data saved in the instance was not encrypted prior to the function call.
        :raises InvalidEncryptedFileExtensionException: If the file to which the data will be written to doesn't end with the
                                                        '.bin' file extension.
        """
        # Validate path:
        self.__validate_file_path(file_path)

        # Saving the data to the specified file:
        with open(file_path, 'wb') as file:
            file.write(self.__encrypted_data)

    def __validate_file_path(self, file_path: str) -> None:
        """
        A utility function whose purpose is to validate the path given to the 'save_to_file' method.
        The function checks the following:
            1) The type of file_path is str.
            2) The encryptor object is not empty (i.e: there is data to write to a file).
            3) The data inside the encryptor object is encrypted (or more precisely, one chunk is encrypted).
            4) The path given is an absolute path.
            5) The path ends with the '.bin' extension.
        If any of these requirements are not met, the function will raise an appropriate exception.
        :param file_path: The path parameter which will be validated.
        :raises ValueError: If the given path isn't an absolute path.
        :raises DataNotLoadedException: If no data is saved in the instance.
        :raises DataNotEncryptedException: If the data saved in the instance was not encrypted prior to the function call.
        :raises InvalidEncryptedFileExtensionException: If the file to which the data will be written to doesn't end with the
                                                        '.bin' file extension.
        """
        # Checking the type of the file_path:
        if type(file_path) != str:
            raise TypeError(f"Expected file path of type str, got {type(file_path)} instead")
        # Checking there is data to write to a file:
        elif self.is_empty():
            raise DataNotLoadedException(
                'Cannot save encrypted data to file because data was cleared or not loaded at all')
        # Checking if the data wasn't encrypted:
        elif not self.is_encrypted():
            raise DataNotEncryptedException('Data must be encrypted before being saved to a file')
        # Checking that the file path is absolute:
        elif not os.path.isabs(file_path):
            raise ValueError(f'The function only accepts absolute paths, yet a relative path was given ({file_path})')
        # Checking that the file path ends with the '.bin' extension:
        elif not file_path.endswith('.bin'):
            raise InvalidEncryptedFileExtensionException("Can only save encrypted data to files ending with '.bin'")

    def save_to_files(self, dir_path: str) -> None:
        """
        Encrypts all saved chunks in the instance and saves the encrypted result into separate files inside the specified
        directory path (if the directory is not made the function will create it). Pay attention that after the data will be
        written into a file, it will be cleared from the instance.
        If any I/O operation fails, the function will remove any files it managed to create prior to the exception. In this
        case, the raw data will still be cleared in order to prevent inconsistencies (for example the crash may happen in the
        third chunk or the fifth or any other, so the remaining data will be of inconsistent size).
        :param dir_path: The absolute path to the directory where the encrypted chunks will be written.
        :type dir_path: str
        :raises IOError: If any I/O operation had failed.
        :raises ValueError: If the given path isn't an absolute path.
        """
        # Checking there is data to write to a file:
        if self.is_empty():
            raise DataNotLoadedException('Cannot save encrypted data to file because data was cleared or not loaded at all')

        # Making sure the path is a string:
        elif type(dir_path) != str:
            raise TypeError(f'Expected directory path of type string, got {type(dir_path)} instead')

        # Making sure the path is absolute (and not relative) so encrypted files won't be saved to the package:
        elif not os.path.isabs(dir_path):
            raise ValueError(f'The function only accepts absolute paths, yet a relative path was given ({dir_path})')

        # The current chunk number:
        chunk_num = 0
        # A variable for any IO exception that may arise:
        io_error = None

        # Wrapping the creation of files in a try block to handle IO errors:
        try:
            # Looping until all chunks were written:
            while not self.is_empty():
                # Encrypt data if it isn't encrypted already:
                if not self.is_encrypted():
                    self.encrypt_data()

                # Saving the chunk:
                chunk_path = os.path.join(dir_path, fr"{Encryptor.CHUNK_NAME.format(chunk_num)}")
                with open(chunk_path, 'wb') as chunk_file:
                    chunk_file.write(self.__encrypted_data)

                # Popping the chunk and incrementing chunk_num:
                chunk_num += 1
                self.pop_chunk()

        # If an error occurred:
        except IOError as ioe:
            # Clear saved chunks:
            Encryptor.__delete_unfinished_files(dir_path, chunk_num)
            # Save the error:
            io_error = ioe
        finally:
            # Clear the data if it isn't cleared already:
            if not self.is_empty():
                self.clear_data()

            # Raise the io exception if one was caught:
            if io_error is not None:
                raise io_error

    @staticmethod
    def __delete_unfinished_files(dir_path: str, chunks_saved: int) -> None:
        """
        When using the "save_to_files" method, and IO exception could be thrown while file creation is still
        in progress. In such case, all previously created files (parts of the encryption) will be removed,
        since the complete data was not successfully encrypted.
        This method is responsible for the deletion of such files.
        :param dir_path: The absolute path to the directory where the chunks were saved.
        :param chunks_saved: The amount of chunks successfully saved prior to the IO exception.
        """
        # Loop over the files and delete them:
        for chunk_num in range(chunks_saved + 1):
            # Get path to the current file:
            path_to_remove = os.path.join(dir_path, fr"{Encryptor.CHUNK_NAME.format(chunk_num)}")

            # Make sure the file exists (and is in fact a file):
            if os.path.exists(path_to_remove) and os.path.isfile(path_to_remove):
                os.remove(path_to_remove)

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
