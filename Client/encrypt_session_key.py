from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from os import urandom
import os
import socket
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Generates a random session key and signs it for authentication and 

with open("client_private_key.pem", "rb") as f:
    private_key_client_data = f.read()
private_key_client = serialization.load_pem_private_key(private_key_client_data, password=None, backend=default_backend())

# Load client's public key
with open("client_public_key.pem", "rb") as f:
    public_key_client_data = f.read()
public_key_client = serialization.load_pem_public_key(public_key_client_data, backend=default_backend())

# Load server's public key
with open("server_public_key.pem", "rb") as f:
    public_key_server_data = f.read()
public_key_server = serialization.load_pem_public_key(public_key_server_data, backend=default_backend())

def sign_data(data, private_key):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def encrypt(data, public_key):
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

# Generate a session key
session_key = urandom(16)  # 128-bit session key
print(session_key)

# Store the session key securely (for demonstration, you can replace 'session_key.bin' with your desired filename)
with open('session_key.bin', 'wb') as session_key_file:
    session_key_file.write(session_key)

print("Session key generated and stored securely.")


# Sign the session key with the client's private key
signature = sign_data(session_key, private_key_client)

# Encrypt the session key using the server's public key
encrypted_session_key = encrypt(session_key, public_key_server)

# Store the encrypted session key securely (for demonstration, you can replace 'session_key.bin' with your desired filename)
with open('encrypted_session_key.bin', 'wb') as session_key_file:
    session_key_file.write(encrypted_session_key)

print("Session key generated and stored securely.")


