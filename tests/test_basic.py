import os
import base64

import pytest
from friendlycrypto import Cryptographer


@pytest.mark.parametrize('salt', (
    bytes(0),
    b'abcdef',
    os.urandom(16),
    os.urandom(128),
    os.urandom(1024),
))
@pytest.mark.parametrize('data', (
    b'secured data',
))
@pytest.mark.parametrize('password', (
    b'MySecur3Pas5w0rd',
    base64.b64encode(b'This is my password!\n'),
))
def test_encryption_decryption(salt, data, password):
    crypto = Cryptographer(salt=salt)
    encrypted = crypto.encrypt(data, password)
    decrepted = crypto.decrypt(encrypted, password)

    assert data == decrepted, "Decrepted data doesn't match original data"
