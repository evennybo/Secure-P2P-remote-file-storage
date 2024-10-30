import bluetooth
import pickle  # Add this import
import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Establish connection
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

    # Send confirmation to the client that session key has been received
    client_sock.send(b"Session key received.")

    # file path for scalability we used session key, but because of isues creating the file some time we changed
    file_path = "encrypted_file.bin"

    # Read the content from the file
    with open(file_path, 'rb') as file:
        content = file.read()

    # Read the IV from the file
    with open('iv.bin', 'rb') as iv_file:
        iv = iv_file.read()

    # Create AES cipher object with CFB mode for session key encryption
    session_cipher = Cipher(algorithms.AES(decrypted_session_key), modes.CFB(iv), backend=default_backend())

    # Create encryptor object for session key encryption
    session_encryptor = session_cipher.encryptor()

    # Encrypt the already encrypted content with the session key
    encrypted_with_session_key = session_encryptor.update(content) + session_encryptor.finalize()

    encrypted_data = iv + encrypted_with_session_key

    with open(file_path, "wb") as f:
        f.write(encrypted_data)


    with open(file_path, 'rb') as file:
        # First, let the server know how big the file is
        file_size = os.path.getsize(file_path)
        file_size_b = str(file_size).encode()
        client_sock.send(file_size_b)

        # Second, wait for confirmation: server should send back file size
        ack = client_sock.recv(1024)
        if file_size != int(ack.decode()):
            raise Exception("Server data size ACK failure.")

        # Third, send the data in blocks of 1024 bytes
        data_sent = 0
        while True:
            data = file.read(1024)
            if len(data) == 0:
                break
            client_sock.send(data)
            data_sent += len(data)
            print("===============> Sending [", len(data), data_sent, "bytes]")

        # Wait for confirmation of session key receipt
        received_file = client_sock.recv(1024)
        print("Received file:", received_file)

        # Deletes the encryoted alice text
        if os.path.exists(file_path):
            os.remove(file_path)
            print("Encrypted content file deleted from server.")


except Exception as e:
    print("Error:", e)
finally:
    client_sock.close()
    server_sock.close()
