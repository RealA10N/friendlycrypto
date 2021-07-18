<div align="center">
    <h1><img src="https://raw.githubusercontent.com/RealA10N/friendlycrypto/master/FriendlyCrypto.png" alt="FriendlyCrypto" width="500px"></h1>
    <img src="https://img.shields.io/github/workflow/status/reala10n/friendlycrypto/%E2%9C%94%20Test/master">
    <img src="https://img.shields.io/pypi/v/friendlycrypto">
    <img src="https://img.shields.io/github/stars/reala10n/friendlycrypto?style=social">
</div>


A simple Python module that uses the [Fernet] secure algorithm to encrypt
your Python objects with just one line of code.


# Installation

Simply install using the Python package manager:

```console
pip install friendlycrypto
```

# Usage

## Encrypting bytes

```python
from friendlycrypto import Cryptographer

with open('img.png', 'rb') as original_f:
    # Loads some file in a 'read-bytes' mode.
    original_data = original_f.read()

# Encoding the password string into a bytes-string.
key = input("Key for encryption: ").encode('utf8')

# Encrypt the data usaing the 'Cryptographer' object
grapher = Cryptographer()
encrypted = grapher.encrypt(original_data, key)

with open('img.png.encrypted', 'wb') as encrypted_f:
    # Write the encrypted data back into a new file.
    encrypted_f.write(encrypted)
```

## Encrypting Python objects

```python
from friendlycrypto import FriendlyCryptographer

# The data can be any Python object!
# For this example, we are using a simple dict with strings.
data = {
    'user1': 'password',
    'user2': 'another-password',
}

# Encoding the password string into a bytes-string.
key = input("Key for encryption: ").encode('utf8')

# Encrypt the data usaing the 'FriendlyCryptographer' object
grapher = FriendlyCryptographer()
encrypted = grapher.encrypt(data, key)

with open('data.encrypted', 'wb') as encrypted_f:
    # Write the encrypted data back into a new file.
    encrypted_f.write(encrypted)
```

## Additional arguments

The `Cryptographer` and `FriendlyCryptographer` objects share an `init` method
with two additional arguments:

### salt: `bytes`

Should be a bytes-string (recommended to be at least 16 bytes long).
Those bytes are added to the encrypted data to add additional randomness and
uniqueness to your database.
The salt shouldn't be stored with the database. generate using the [os.urandom]
function.

Read more about the [salt in hashing].

### kdf_iterations: `int`

The module uses a [key derivation function] to convert the given password bytes
into a fixed-length bytes string. Each iteration of the function takes time to
compute, and thus a larger number of iterations makes it harder for attackers
to just guess every option.

The recommended and default value is `100_000`, and on my computer it takes
approximately 0.1 seconds to compute.


[Fernet]: https://github.com/fernet/spec/
[os.urandom]: https://docs.python.org/3/library/os.html#os.urandom
[salt in hashing]: https://auth0.com/blog/adding-salt-to-hashing-a-better-way-to-store-passwords/
[key derivation function]: https://en.wikipedia.org/wiki/Key_derivation_function
