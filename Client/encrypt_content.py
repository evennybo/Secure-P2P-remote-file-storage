from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes

import os

# Function to pad the content to fit AES block size
def pad(content):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(content)
    padded_data += padder.finalize()
    return padded_data


# Open the file in read mode
with open('alice.txt', 'rb') as file:
    # Read the content of the file
    content = file.read()

# Generate a random 128-bit key for AES encryption
aes_key = os.urandom(16)

# Generate a random 16-byte iv
iv = os.urandom(16)

# Store the AES key in a file
with open('aes_key.bin', 'wb') as key_file:
    key_file.write(aes_key)

# Store the IV in a file
with open('iv.bin', 'wb') as iv_file:
    iv_file.write(iv)

# Pad the content
content = pad(content)

# Create AES cipher object with CFB mode
aes_cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())

# Create encryptor object for AES encryption
aes_encryptor = aes_cipher.encryptor()

# Encrypt the content
encrypted_content = aes_encryptor.update(content) + aes_encryptor.finalize()

hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
hasher.update(encrypted_content)
hash_value = hasher.finalize()

print(hash_value)

# Write the hash to a file
with open('hash.bin', 'wb') as hash_file:
    hash_file.write(hash_value)

# Load the session key from the file or generate it
with open('session_key.bin', 'rb') as session_key_file:
    session_key = session_key_file.read()

# Create AES cipher object with CFB mode for session key encryption
session_cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())

# Create encryptor object for session key encryption
session_encryptor = session_cipher.encryptor()

# Encrypt the already encrypted content with the session key
encrypted_with_session_key = session_encryptor.update(encrypted_content) + session_encryptor.finalize()

encrypted_data = iv + encrypted_with_session_key
# Write the doubly encrypted content to a file
with open('encrypted_content.bin', 'wb') as encrypted_file:
    encrypted_file.write(encrypted_data)


print("Encryption completed.")


