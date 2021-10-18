# Import socket module
import socket
import crypto
from Crypto.Cipher import AES
s = socket.socket()


def aes_decoder(block, key):
    # block = crypto.pad_bits_append(block, len(key))
    # block = crypto.bits_to_string(block)
    # key = crypto.bits_to_string(key)
    ecb1 = AES.new(dec_key, AES.MODE_ECB)
    return ecb1.decrypt(block)

initialization_vector = '0102030405060708'
# k'
key = '\xe3N\x90x\x1f\xde\xaa4\xb7\xd2@b\xf9\x1b\xf2l'
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
aes = AES.new(key.encode('utf-8'), AES.MODE_CBC, initialization_vector.encode('utf-8'))
dec_key = aes.decrypt(enc_key)
print(f'Decrypted key = {dec_key}')


# send greetings from B to A
s.send("Hello from Narnia".encode())

# receive messages from A 
while True:  
    message_from_a = s.recv(128) 
    decoded_message = aes_decoder(message_from_a,dec_key) 
    print(decoded_message)

     

# close the connection
s.close()






