import bluetooth
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Load server's public key to encrypt session key for authentication
with open("client_public_key.pem", "rb") as f:
    public_key_client_data = f.read()
public_key_client = serialization.load_pem_public_key(public_key_client_data, backend=default_backend())

# Establish connection with client
server_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
print(bluetooth.read_local_bdaddr())

port = 1  # pick one between 1 and 30
server_sock.bind(("", port))
server_sock.listen(1)

print("Waiting for a connection on RFCOMM port", port)

client_sock, client_info = server_sock.accept()
print("Accepted connection from ", client_info)

try:
    # First, waiting on the session key size
    session_key_size_b = client_sock.recv(1024)
    session_key_size = int(session_key_size_b.decode())
    print("Client is about to send the session key of size:", session_key_size, "bytes")

    # Second, send ACK for session key size
    client_sock.send(session_key_size_b)

    # Third, start receiving session key data
    session_key = b""
    while len(session_key) < session_key_size:
        new_data = client_sock.recv(1024)
        if len(new_data) == 0:
            break

        session_key += new_data

    print("Session key received:", session_key)

    # Load server's private key
    with open("server_private_key.pem", "rb") as f:
        private_key_server_data = f.read()
    private_key_server = serialization.load_pem_private_key(private_key_server_data, password=None, backend=default_backend())

    # Decrypt the session key
    decrypted_session_key = private_key_server.decrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Decrypted session key:", decrypted_session_key)

    # Encrypt the session key and send back for authentication
    encrypted_session_key = public_key_client.encrypt(
        decrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    client_sock.send(encrypted_session_key)


    # Now receiver waits for the encrypted file
    print("Waiting for the encrypted file...")
    # First, waiting on the data size
    size_b = client_sock.recv(1024)
    size = int(size_b.decode())
    print("Client is about to send the encrypted file of size:", size, "bytes")

    # Second, send ACK for encrypted file size
    client_sock.send(size_b)

    # Third, start receiving encrypted file data
    encrypted_file_data = b""
    while len(encrypted_file_data) < size:
        new_data = client_sock.recv(1024)
        if len(new_data) == 0:
            break

        encrypted_file_data += new_data

    print("Encrypted file received.")

    # Extract the IV and encrypted content from the encrypted data
    iv = encrypted_file_data[:16]  

    # Store the IV in a file for future encryption sending back
    with open('iv.bin', 'wb') as iv_file:
        iv_file.write(iv)

    encrypted_with_session_key = encrypted_file_data[16:]

    # Create AES cipher object with CFB mode for session key decryption
    session_cipher = Cipher(algorithms.AES(decrypted_session_key), modes.CFB(iv), backend=default_backend())

    # Create decryptor object for session key decryption
    session_decryptor = session_cipher.decryptor()

    # Decrypt the content with the session key
    decrypted_content = session_decryptor.update(encrypted_with_session_key) + session_decryptor.finalize()

    # Calculates the hash from the symmetric encrypted file to send back to client for integrity
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(decrypted_content)
    calculated_hash_value = hasher.finalize()

    # Save the encrypted file
    with open("encrypted_file.bin", "wb") as f:
        f.write(decrypted_content)

    # Send final acknowledgement
    client_sock.send(calculated_hash_value)

except Exception as e:
    print("Error:", e)
finally:
    client_sock.close()
    server_sock.close()

