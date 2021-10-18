# Import socket module
import socket
from aes import AES
import crypto

s = socket.socket()


initialization_vector = b'0102030405060708'
# k'
key = b'7766554433221100'
port = 7777

# connect to the server on local computer
s.connect(('127.0.0.1', port))

# receive message from A (ECB OR CFB)
message = s.recv(1024).decode()
print(f'Message from A: {message}')

# get encryped key from A
enc_key = s.recv(1024)
print(str(enc_key))

# decrpyt key
aes = AES(key)
dec_key = crypto.decrypt_cfb(aes, enc_key, initialization_vector)

# aes = AES.new(key.encode('utf-8'), AES.MODE_CBC, initialization_vector.encode('utf-8'))
# dec_key = aes.decrypt(enc_key)
print(f'Decrypted key = {dec_key}')


# send greetings from B to A
s.send("Hello from Narnia".encode())

# receive messages from A 
while True:  
    message_from_a = s.recv(32)
    aes = AES(dec_key)
    if message == 'ECB':
        decoded_message = crypto.decrypt_ecb(aes, message_from_a)
        print(f'Decoded block: {decoded_message}')
    else:
        decoded_message = crypto.decrypt_cfb(aes, message_from_a, initialization_vector)
        print(f'Decoded block: {decoded_message}')

    

     

# close the connection
s.close()






