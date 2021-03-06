import aes


def split_blocks(message, block_size=16, require_padding=True):
        assert len(message) % block_size == 0 or not require_padding
        return [message[i:i+16] for i in range(0, len(message), block_size)]

def xor_bytes(a, b):
    return bytes(i^j for i, j in zip(a, b))

def pad(plaintext):
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding

def unpad(plaintext):
    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    assert all(p == padding_len for p in padding)
    return message

def encrypt_cfb(aes_, plaintext, iv):
    blocks = []
    prev_ciphertext = iv
    for plaintext_block in split_blocks(plaintext, require_padding=False):
        # CFB mode encrypt: plaintext_block XOR encrypt(prev_ciphertext)
        ciphertext_block = xor_bytes(plaintext_block, aes_.encrypt_block(prev_ciphertext))
        blocks.append(ciphertext_block)
        prev_ciphertext = ciphertext_block

    return b''.join(blocks)


def encrypt_ecb(aes_, plaintext):
    blocks = []

    plaintext = pad(plaintext)

    for plaintext_block in split_blocks(plaintext):
        ciphertext_block = aes_.encrypt_block(plaintext_block)
        blocks.append(ciphertext_block)

    return b''.join(blocks)

def decrypt_ecb(aes_, ciphertext):
    blocks = []

    for ciphertext_block in split_blocks(ciphertext):
        plaintext_block = aes_.decrypt_block(ciphertext_block)
        blocks.append(plaintext_block)

    return unpad(b''.join(blocks))

def decrypt_cfb(aes_, ciphertext, iv):
    blocks = []
    prev_ciphertext = iv
    for ciphertext_block in split_blocks(ciphertext, require_padding=False):
        plaintext_block = xor_bytes(ciphertext_block, aes_.encrypt_block(prev_ciphertext))
        blocks.append(plaintext_block)
        prev_ciphertext = ciphertext_block

    return b''.join(blocks)


