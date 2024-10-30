import socket
import pickle
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


# Function to unpad the content after AES decryption
def unpad(padded_content):
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(padded_content)
    unpadded_data += unpadder.finalize()
    return unpadded_data

# Deletes the files after recieving the text file back
def delete_files(file_list):
            for file_path in file_list:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"{file_path} deleted.")
                else:
                    print(f"{file_path} does not exist.")

try:

    target_addr = "B8:27:EB:29:FA:9B"  # replace with device address
    target_port = 1

    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
    sock.connect((target_addr, target_port))

    key_file_path = "encrypted_session_key.bin"
    with open(key_file_path, 'rb') as file:
        # First, let the server know how big the file is
        file_size = os.path.getsize(key_file_path)
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


        # Receive the encrypted file size
        file_size_b = sock.recv(1024)
        file_size = int(file_size_b.decode())
        print("Server is about to send the encrypted file of size:", file_size, "bytes")

        # Send ACK for encrypted file size
        sock.send(file_size_b)

        # Third, start receiving encrypted file data
        encrypted_file_data = b""
        while len(encrypted_file_data) < file_size:
            new_data = sock.recv(1024)
            if len(new_data) == 0:
                break

            encrypted_file_data += new_data

        print("Encrypted file received.")

        # Load the session key from the file or wherever it's stored
        with open('session_key.bin', 'rb') as session_key_file:
            session_key = session_key_file.read()

        # Extract the IV and encrypted content from the encrypted data
        iv = encrypted_file_data[:16]  

        encrypted_with_session_key = encrypted_file_data[16:]

        # Create AES cipher object with CFB mode for session key decryption
        session_cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())

        # Create decryptor object for session key decryption
        session_decryptor = session_cipher.decryptor()

        # Decrypt the content
        decrypted_content = session_decryptor.update(encrypted_with_session_key) + session_decryptor.finalize()

        # Read the IV from the file
        with open('iv.bin', 'rb') as iv_file:
            iv = iv_file.read()

        # Read the AES key from the file
        with open('aes_key.bin', 'rb') as key_file:
            aes_key = key_file.read()

        # Create AES cipher object with CFB mode
        aes_cipher_decrypt = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())

        # Create decryptor object for AES decryption
        aes_decryptor = aes_cipher_decrypt.decryptor()

        # Decrypt the content
        decrypted_content = aes_decryptor.update(decrypted_content) + aes_decryptor.finalize()

        # Unpad the decrypted content
        unpadded_content = unpad(decrypted_content)

        # Store the file back securely 
        with open('content.txt', 'w') as f:
            f.write(unpadded_content.decode('utf-8'))

        # Deletes necessary files
        file_list = ["iv.bin", "aes_key.bin", "session_key.bin", "encrypted_session_key.bin"]
        delete_files(file_list)

except Exception as e:
    print("Error:", e)
finally:
    sock.close()




