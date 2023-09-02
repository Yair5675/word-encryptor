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
