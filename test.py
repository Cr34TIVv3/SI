import aes
import crypto


def main():
    key = b'0011223344556677'
    key_ = b'7766554433221100'
    initialization_vector = b'0102030405060708'


    aes_ = aes.AES(key_)
    
    enc = crypto.encrypt_cfb(aes_, key, initialization_vector)
    print(enc)

    dec = crypto.decrypt_cfb(aes_, enc, initialization_vector)
    print(dec)


main()