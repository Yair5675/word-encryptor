class Decryptor:
    """
    A class that is used to decrypt encrypted data using a password-based key. The class is meant to decrypt data which was
    encrypted using the Encryptor class, therefor it is not for general purpose decryption.
    """
    __slots__ = [
        '__password'  # The password used during the encryption. It is needed to reverse the process
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
