import aes
import crypto


def main():
    key = b'0011223344556677001122334455667700112233445566770011223344556677'
    key_ = b'7766554433221100'
    initialization_vector = b'0102030405060708'

    with open("secret.txt", "r") as f:
            message = f.read()
            aes_ = aes.AES(key_)
            
            enc = crypto.encrypt_cfb(aes_, bytes(message, 'utf-8'), initialization_vector)
            # enc = crypto.encrypt_ecb(aes_, bytes(message, 'utf-8'))
            # enc = crypto.encrypt_ecb(aes_, key[0:16])
            print(enc)

            dec = crypto.decrypt_cfb(aes_, enc, initialization_vector)
            # dec = crypto.decrypt_ecb(aes_, enc)
            print(dec)


main()