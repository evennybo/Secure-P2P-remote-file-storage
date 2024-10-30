import os
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Load the session key for authetication
with open("session_key.bin", "rb") as f:
            session_key = f.read()

encrypted_content_file = "encrypted_content.bin"
alice_txt_file = "alice.txt"

# Loads client private key for decrypting session key coming back from server for authentication
with open("client_private_key.pem", "rb") as f:
    private_key_client_data = f.read()
private_key_client = serialization.load_pem_private_key(private_key_client_data, password=None, backend=default_backend())


try:
    target_addr = "B8:27:EB:29:FA:9B"  # replace with device address
    target_port = 1

    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
    sock.connect((target_addr, target_port))

    file_path = "encrypted_session_key.bin"
    with open(file_path, 'rb') as file:
        # First, let the server know how big the file is
        file_size = os.path.getsize(file_path)
        file_size_b = str(file_size).encode()
        sock.send(file_size_b)

        # Second, wait for confirmation: server should send back file size
        ack = sock.recv(1024)
        if file_size != int(ack.decode()):
            raise Exception("Server data size ACK failure.")

        # Third, send the data in blocks of 1024 bytes
        data_sent = 0
        while True:
            data = file.read(1024)
            if len(data) == 0:
                break
            sock.send(data)
            data_sent += len(data)
            print("===============> Sending [", len(data), data_sent, "bytes]")

        # Wait for confirmation of session key receipt
        received_session_key = sock.recv(1024)
        print("Received session key:", received_session_key)

        # Decrypt the session key
        decrypted_session_key = private_key_client.decrypt(
            received_session_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print("Decrypted session key:", decrypted_session_key)

        # Checks if session keys matches from the server for authentication
        if decrypted_session_key != session_key:
            raise Exception("Decrypted session key does not match the original session key.")

    # Now send encrypted content
    with open(encrypted_content_file, 'rb') as file:
        # First, let the server know how big the file is
        file_size = os.path.getsize(encrypted_content_file)
        file_size_b = str(file_size).encode()
        sock.send(file_size_b)

        # Second, wait for confirmation: server should send back file size
        ack = sock.recv(1024)
        if file_size != int(ack.decode()):
            raise Exception("Server data size ACK failure.")

        # Third, send the data in blocks of 1024 bytes
        data_sent = 0
        while True:
            data = file.read(1024)
            if len(data) == 0:
                break
            sock.send(data)
            data_sent += len(data)
            print("===============> Sending [", len(data), data_sent, "bytes]")


        # Load the hash for integrity check
        with open('hash.bin', 'rb') as hash_file:
            hash_value = hash_file.read()

        # Wait for final acknowledgment
        final_ack = sock.recv(1024)
        print("Final acknowledgment from server:", final_ack.decode())

        if hash_value == final_ack.decode():
            print("Integrity check passed, now delete the file")
            # Deletes the encryoted alice text
            if os.path.exists(encrypted_content_file):
                os.remove(encrypted_content_file)
                print("Encrypted content file deleted.")

            # Delete the original plaintext file (alice.txt)
            if os.path.exists(alice_txt_file):
                os.remove(alice_txt_file)
                print("Original plaintext file deleted.")
        else:
            print("Integrity check failed")


except Exception as e:
    print("Send failure:", e)
finally:
    print("Content sent.")
    sock.close()
