from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# This generates the private and public key for both client and server

def generate_rsa_key_pair():
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Generate the public key
    public_key = private_key.public_key()

    # Serialize private key to PEM format
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key to PEM format
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private, pem_public

# Generate client pair of keys
private_key_client, public_key_client = generate_rsa_key_pair()
# Generate server pair of keys
private_key_server, public_key_server = generate_rsa_key_pair()

# Store keys in separate files
with open("client_private_key.pem", "wb") as f:
    f.write(private_key_client)
with open("client_public_key.pem", "wb") as f:
    f.write(public_key_client)
with open("server_private_key.pem", "wb") as f:
    f.write(private_key_server)
with open("server_public_key.pem", "wb") as f:
    f.write(public_key_server)
