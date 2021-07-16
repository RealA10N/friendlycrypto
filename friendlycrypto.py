"""

Why the password can't be any Python object, similarly to the data?
===================================================================

In short: pickling two identical Python objects doesn't guarantee that the
pickled bytes will be equal. https://docs.python.org/2/library/pickle.html#id20

I wanted to be able to use regular Python objects as the data encrypted as well
as the password/key for the encryption. However, while testing I found out that
sometimes (in a fairly unpredictable manner), when pickleing two identical
Python objects they can result in a different pickle bytes string, which ruins
the idea of Python objects acting as a password.

I have been researching since, but couldn't find a better way to convert any
Python object into a one-to-one bytes-string, and thus, passwords are left to
the user to convert into a byte-string.

"""
import base64
import pickle

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


__version__ = '1.0.0'
__all__ = [
    'Cryptographer',
    'FriendlyCryptographer',
    'DecryptionError',
]


class DecryptionError(Exception):
    """ An error raised when the decryption proccess fails. """


class Cryptographer:
    """ Easily encrypt and decrypt strings of bytes using a byte-string password. """

    def __init__(self,
                 salt: bytes = b'',
                 kdf_iterations: int = 100_000,
                 ) -> None:
        self.salt = salt
        self.kdf_iterations = kdf_iterations

    def _key_from_password(self, password: bytes) -> PBKDF2HMAC:
        """ Converts the given password bytes into a short and 32byte key
        that will be used with the `Fernet` encryption algorithm. """

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Bytes
            salt=self.salt,
            iterations=self.kdf_iterations,
        )

        key = kdf.derive(password)

        # The `cryptography` library uses url-safe base64 encoded strings,
        # And thus the key is being encoded.
        return base64.urlsafe_b64encode(key)

    def encrypt(self, data: bytes, password: bytes) -> bytes:
        """ Recives a `data` bytes string with an additional `password` bytes
        string, and returns the encrepted bytes string. The length of the returned
        bytes-string should be more or less equal to the received data length. """

        key = self._key_from_password(password)
        fernet = Fernet(key)
        safe_encrypted = fernet.encrypt(data)

        # The `cryptography` library returns the encrypted data after encoding
        # it using the url-safe base64 encoding. This library is meant to be used
        # locally, and thus, to save local space, the data is decoded to the basic
        # bytes representation.
        return base64.urlsafe_b64decode(safe_encrypted)

    def decrypt(self, data: bytes, password: bytes) -> bytes:
        """ Decrypts the given byte-string data using the given byte-string password,
        and returns the original data as a byte-string. """

        key = self._key_from_password(password)
        fernet = Fernet(key)

        # The `cryptography` library
        safe_data = base64.urlsafe_b64encode(data)

        try:
            # Try to decrypt
            return fernet.decrypt(safe_data)

        except InvalidToken:
            # If the `cryptography` library raises an error,
            # raise a custom `DecryptionError`. This is done to avoid the user
            # from importing the `InvalidToken` exception from the 3rd-party
            # `cryptography` library if the user wants to catch this exception.

            raise DecryptionError(
                'The decryption process was not preformed successfully.'
            ) from None


class FriendlyCryptographer(Cryptographer):
    """ Has the same `encrypt` and `decrypt` methods as the `Cryptographer`,
    but is not limited to only byte-strings, and now supports encryption and
    decryption of all Python objects.

    # How does it work?

    1)  The `encrypt` method recives the data as a regular Python object.
    2)  Using the `pickle` module, the data is converted to a byte-strings that
        represent the object.
    3)  The password bytes are then passed to a `Password-Based Key Derivation
        Function` that converts those bytes into a short, length fixed byte string
        that will be used as the key. It is possible to add salt to this process
        using the salt argument in the constructor.
    4)  The pickled data is encrypted using the `Fernet` algorithm from the
        `cryptography` module.

    """

    def encrypt(self, data, password: bytes) -> bytes:
        """ Recives `data` and encrypts it into a string of bytes using the
        given `password`. `data` can be any Python object, including regular
        string, byte-strings, number, dictionaries, and complex objects and
        instances of custom created classes. `password` must be a bytes-like
        object. """

        return super().encrypt(
            pickle.dumps(data),
            password,
        )

    def decrypt(self, data: bytes, password: bytes):
        """ Recives an encrepted bytes-string and the password bytes, and
        returns the original Python object that was encrypted using the
        password. """

        decrepted_bytes = super().decrypt(
            data,
            password,
        )

        return pickle.loads(decrepted_bytes)
