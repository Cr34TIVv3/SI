# Import socket module
import crypto
from Crypto.Cipher import AES
initialization_vector = '0102030405060708'

def xor_encoder(block, key):
    block = crypto.pad_bits_append(block, len(key))
    cipher = [b ^ k for b, k in zip(block, key)]
    return cipher

def aes_encoder(block, key):
    block = crypto.pad_bits_append(block, 128)
    ecb = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    return (ecb.encrypt(str.encode(block)))


def ecb(plaintext, key, block_size):
    # break the plaintext into blocks
    # and encode each one using ECB 
    cipher = []
    for i in range(len(plaintext) // block_size + 1):
        start = i * block_size
        if start >= len(plaintext):
            break
        end = min(len(plaintext), (i+1) * block_size)
        block = plaintext[start:end]
        cipher.append (aes_encoder(block,key))
        #send cipher text to B
        

    return cipher

def main():
  
    # k'
    dec_key = '\xe3N\x90x\x1f\xde\xaa4\xb7\xd2@b\xf9\x1b\xf2l'
   

    with open("secret.txt", "r") as f:
        message = f.read(1024)
        sentences = ecb(message, dec_key, 128)
        ecb1 = AES.new(dec_key.encode('utf-8'), AES.MODE_ECB)
        for sentence in sentences: 
            print(ecb1.decrypt(sentence))



main()


