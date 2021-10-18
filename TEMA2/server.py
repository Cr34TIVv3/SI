import socket
import secrets
import sys
from Crypto.Cipher import AES

#K' and IV
k_ = '\xe3N\x90x\x1f\xde\xaa4\xb7\xd2@b\xf9\x1b\xf2l'
initialization_vector = '0102030405060708'


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
    aes = AES.new(k_.encode('utf-8'), AES.MODE_CBC, initialization_vector.encode('utf-8'))
    enc_key = aes.encrypt(k)
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
        message_for_b = client_a.recv(128)
        client_b.send(message_for_b)


    client_a.close()
    client_b.close()


if __name__ == '__main__':
    main()
