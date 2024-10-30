## README

### Assumption

We Assume that the private and public keys are already generated. Also that the client encrypt the session key and it file before sending it


### Installing cryptography library

You need to install the `cryptography` and `pybluez` libraries to use cryptographic functionalities and bluetooth.

```bash
pip install cryptography

pip install pybluez

```
### Setup

1. Ensure that the client and server each have their private and public keys, as well as the server's public key. If not, run `generate_keys.py` on both the client and server sides to generate the necessary keys. After generation, delete the private key files from the opposite side to maintain security.

### Sending a File to the Server

1. Run `Receive.py` on the server to establish a connection and wait for the client's response.
2. Run `encrypt_session_key.py` on the client to generate the session key and encrypt it using the server's public key.
3. Run `encrypt_content.py` on the client to encrypt the file that will be sent to the server.
4. After running the above files, execute `send.py` on the client side. This sends both the encrypted session key and the encrypted file to the server.

### Retrieving a File from the Server

1. Run `Send.py` on the server side to establish a connection and wait for the client's request.
2. Run `Retrieve.py` on the client side to send the encrypted session key for authentication and initiate the file retrieval process.
3. Upon receiving the encrypted session key, the server sends the encrypted file back to the client.

### Conclusion

By following these steps, you can securely send and retrieve files between the client and server over a Bluetooth connection, ensuring confidentiality and integrity through encryption and authentication mechanisms.
