import socket
import secrets
from aes import AES
import crypto

#K' and IV
k_ = b'7766554433221100'
initialization_vector = b'0102030405060708'


def generate_random_key():
    return secrets.token_bytes(16)


def main():
    server = socket.socket()
    port = 7777
    server.bind(('', port))

    server.listen(5)
    print("Server started...")

    client_a, address_a = server.accept()
    client_b, address_b = server.accept()

    # message from A for B (ECB OR CFB)
    message_for_b = client_a.recv(1024).decode()
    print(message_for_b)

    # sent message to B (ECB OR CFB)
    client_b.send(message_for_b.encode())

    # crypt key for A
    k = generate_random_key()
    print(f'Key generated : {k}')

    aes = AES(k_) 
    enc_key = crypto.encrypt_cfb(aes, k, initialization_vector)
    print(f'Encrypted key = {enc_key}')


    # send encryped key to A
    client_a.send(enc_key)

    # receive encrypted key from A and send it to B
    enc_key = client_a.recv(1024)
    client_b.send(enc_key)


    # receive greetings from B and send it to A
    message = client_b.recv(1024)
    client_a.send(message)

    # receive messages from A and send it to B
    while True:
        message_for_b = client_a.recv(32)
        client_b.send(message_for_b)

    client_a.close()
    client_b.close()


if __name__ == '__main__':
    main()
