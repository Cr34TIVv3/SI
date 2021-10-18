# Import socket module
import socket
import crypto
from Crypto.Cipher import AES


def xor_encoder(block, key):
    block = crypto.pad_bits_append(block, len(key))
    cipher = [b ^ k for b, k in zip(block, key)]
    return cipher


def aes_encoder(block, key, initialization_vector = 0):
    if initialization_vector == 0:
        block = crypto.pad_bits_append(block, 128)
        ecb = AES.new(key, AES.MODE_ECB)
        return (ecb.encrypt(str.encode(block)))
    else:
        block = crypto.pad_bits_append(block, 128)

        block = xor_encoder(block,initialization_vector)

        ecb = AES.new(key, AES.MODE_CFB,initialization_vector.encode('utf-8')) 
        return (ecb.encrypt(str.encode(block)))


def ecb(plaintext, key, block_size, s):
    # break the plaintext into blocks
    # and encode each one using ECB 
    for i in range(len(plaintext) // block_size + 1):
        start = i * block_size
        if start >= len(plaintext):
            break
        end = min(len(plaintext), (i+1) * block_size)
        block = plaintext[start:end]
        cipher = aes_encoder(block,key)
        #send cipher text to B 
        s.send(cipher)


def cfb(plaintext, key, initialization_vector, block_size, s):
    # break the plaintext into blocks
    # and encode each one using CFB
    
    for i in range(len(plaintext) // block_size + 1):
        start = i * block_size
        if start >= len(plaintext):
            break
        end = min(len(plaintext), (i+1) * block_size)
        block = plaintext[start:end]
        cipher = aes_encoder(block,key,initialization_vector)
        #send cipher text to B 
        s.send(cipher)

def main():
    s = socket.socket()
    operation_mode = 'ECB'
    # k' and IV
    key = '\xe3N\x90x\x1f\xde\xaa4\xb7\xd2@b\xf9\x1b\xf2l'
    initialization_vector = '0102030405060708'

    port = 7777

    # connect to the server on local computer
    s.connect(('127.0.0.1', port))

    # send ECB or CFB to B
    s.send(operation_mode.encode())

    # get encryped key from KM
    enc_key = s.recv(1024)
    print(str(enc_key))

    # decrypt key
    aes = AES.new(key.encode('utf-8'), AES.MODE_CBC, initialization_vector.encode('utf-8'))
    dec_key  = aes.decrypt(enc_key)
    print(f'Decrypted key = {dec_key}')

    # send encrypted key to B
    s.send(enc_key)

    # receive greeting message from B
    print(s.recv(1024).decode())

    # send file to B either in ECB or CFB mode
    with open("secret.txt", "r") as f:
        message = f.read(1024)
        if operation_mode == 'ECB':
           ecb(message, dec_key, 128, s)
        else: 
           cfb(message, dec_key, initialization_vector, 128, s)

    s.close()


main()








