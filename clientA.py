import socket
from aes import AES
import crypto



def main():
    s = socket.socket()
    # operation_mode = 'CFB'
    operation_mode = 'ECB'
    # k' and IV
    key = b'7766554433221100'
    initialization_vector = b'0102030405060708'

    port = 7777

    # connect to the server on local computer
    s.connect(('127.0.0.1', port))

    # send ECB or CFB to B
    s.send(operation_mode.encode())

    # get encryped key from KM
    enc_key = s.recv(1024)
    print(str(enc_key))

    # decrypt key
    aes = AES(key)
    dec_key = crypto.decrypt_cfb(aes, enc_key, initialization_vector)
    
    # aes = AES.new(key.encode('utf-8'), AES.MODE_CBC, initialization_vector.encode('utf-8'))
    # dec_key  = aes.decrypt(enc_key)
    print(f'Decrypted key = {dec_key}')

    # send encrypted key to B
    s.send(enc_key)

    # receive greeting message from B
    print(s.recv(1024).decode())

    # send file to B either in ECB or CFB mode
    with open("secret.txt", "r") as f:
        message = f.read(1024)
        aes = AES(dec_key)
        blocks = [message[i:i+16] for i in range(0, len(message), 16)]
        if operation_mode == 'ECB':
            for block in blocks:
                encrypted_message = crypto.encrypt_ecb(aes, bytes(block, 'utf-8'))
                s.send(encrypted_message)
                print(f'Message : {block}')
                print(f'(CFB) Message sent: {encrypted_message}')
        else: # CFB
            for block in blocks:
                encrypted_message = crypto.encrypt_cfb(aes, bytes(block, 'utf-8'), initialization_vector)
                s.send(encrypted_message)
                print(f'Message : {block}')
                print(f'(CFB) Message sent: {encrypted_message}')
            

    s.close()


main()








