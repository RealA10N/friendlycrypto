import os
import base64
from copy import deepcopy

import pytest
from friendlycrypto import FriendlyCryptographer


class ExampleObj:

    def __init__(self, **kwargs):
        self.kwargs = kwargs


@pytest.mark.parametrize('salt', (
    bytes(0),
    b'abcdef',
    os.urandom(16),
    os.urandom(128),
    os.urandom(1024),
))
@pytest.mark.parametrize('data', (
    b'secured data',
    'regular string data',
    {'key': 'value', 'another': 123},
    {1, 2, 3, 'hello!'},
    123,
    None,
    object(),
    ExampleObj,
    ExampleObj(),
    ExampleObj(hello='hi', test=True, more=ExampleObj(more=None))
))
@pytest.mark.parametrize('password', (
    b'MySecur3Pas5w0rd',
    base64.b64encode(b'This is my password!\n'),
    'MyPassword'.encode('utf8'),
    int.to_bytes(2102, 2, 'big'),
))
def test_encryption_decryption(salt, data, password):

    # Simulating two different instances of passwords that contain the
    # same data. An example of this scenario will be when the data is
    # decrypted in one script, and then decrypted using different instance
    # from a different script, but the new instance contains the same data.
    passcopy = deepcopy(password)

    # Encrypt the data using one instance of the password,
    # and decrypt it using the other one. If the decryption process fails,
    # an `DecryptionError` will be raised and the test will fail.
    # kdf_iteration=1 for faster testing.
    crypto = FriendlyCryptographer(salt=salt, kdf_iterations=1)
    encrypted = crypto.encrypt(data, password)
    crypto.decrypt(encrypted, passcopy)

    # There is no need to test for equality between and original and decrypted
    # data: if the decreption is successful, the Fermet algorithm guarantees
    # that the data is valid.
    # There is not easy and straight forward way to compare between two
    # different instances (original and after the encryption and decryption)
    # process (the equality operator will work for simple objects but not
    # guaranteed for every custom object), and thus we just don't!
