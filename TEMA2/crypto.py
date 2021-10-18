from Crypto.Cipher import AES

def non_encoder(block, key):
    return pad_bits_append(block, len(key))

def xor_encoder(block, key):
    block = pad_bits_append(block, len(key))
    cipher = [b ^ k for b, k in zip(block, key)]
    return cipher

def aes_encoder(block, key):
    block = pad_bits_append(block, len(key))
    block = bits_to_string(block)
    key = bits_to_string(key)
    ecb = AES.new(key, AES.MODE_ECB)
    return string_to_bits(ecb.encrypt(block))


def electronic_codebook(plaintext, key, block_size, block_enc):
    cipher = []
    # break the plaintext into blocks
    # and encode each one
    for i in range(len(plaintext) / block_size + 1):
        start = i * block_size
        if start >= len(plaintext):
            break
        end = min(len(plaintext), (i+1) * block_size)
        block = plaintext[start:end]
        cipher.extend(block_enc(block, key))
    return cipher


def cipher_block_chaining(plaintext, key, init_vec, block_size, block_enc):
    cipher = []
    # break the plaintext into blocks
    # and encode each one
    cipher.extend(init_vec)
    for i in range(len(plaintext) / block_size + 1):
        start = i * block_size
        if start >= len(plaintext):
            break
        end = min(len(plaintext), (i+1) * block_size)
        block = plaintext[start:end]
        pre = cipher[start:end]
        m = [int(block[j] != pre[j]) for j in range(len(pre))]
        
        cipher.extend(block_enc(m, key))
    return cipher[block_size:]
    


BITS = ('0', '1')
ASCII_BITS = 8

def display_bits(b):
    return ''.join([BITS[e] for e in b])

def seq_to_bits(seq):
    return [0 if b == '0' else 1 for b in seq]

def pad_bits(bits, pad):
    assert len(bits) <= pad
    return [0] * (pad - len(bits)) + bits
        
def convert_to_bits(n):
    result = []
    if n == 0:
        return [0]
    while n > 0:
        result = [(n % 2)] + result
        n = n / 2
    return result

def string_to_bits(s):
    def chr_to_bit(c):
        return pad_bits(convert_to_bits(ord(c)), ASCII_BITS)
    return [b for group in 
            map(chr_to_bit, s)
            for b in group]


def list_to_string(p):
    return ''.join(p)


def bits_to_char(b):
    print(f'--- {b}')
    assert len(b) == ASCII_BITS
    value = 0
    for e in b:
        value = (value * 2) + e
    return chr(value)


def bits_to_string(b):
    return ''.join([bits_to_char(b[i:i + ASCII_BITS]) 
                    for i in range(0, len(b), ASCII_BITS)])

def pad_bits_append(small, size):
    diff = max(0, size - len(small))
    for i in range(diff):
        small = small + '0' 
    return small 
    # return small + str([0] * diff)

# def test():
#     key = string_to_bits('4h8f.093mJo:*9#$')
#     iv = string_to_bits('89JIlkj3$%0lkjdg')
#     plaintext = string_to_bits("One if by land; two if by sea")

#     cipher = cipher_block_chaining(plaintext, key, iv, 128, aes_encoder)
#     print len(iv), len(plaintext), len(cipher)
#     print display_bits(cipher)
#     print display_bits(string_to_bits('\xeaJ\x13t\x00\x1f\xcb\xf8\xd2\x032b\xd0\xb6T\xb2\xb1\x81\xd5h\x97\xa0\xaeogtNi\xfa\x08\xca\x1e'))
#     assert bits_to_string(cipher) == '\xeaJ\x13t\x00\x1f\xcb\xf8\xd2\x032b\xd0\xb6T\xb2\xb1\x81\xd5h\x97\xa0\xaeogtNi\xfa\x08\xca\x1e'

#     cipher = cipher_block_chaining(plaintext, key, iv, 128, non_encoder)
#     assert bits_to_string(cipher) == 'wW/i\x05\rJQ]\x05\\\r\x05\x0e_G\x03 @Ilkj3$%/hd\x00\x00\x00'

#     cipher = cipher_block_chaining(plaintext, key, iv, 128, xor_encoder)
#     assert bits_to_string(cipher) == 'C?\x17\x0f+=sb0O37/7|c\x03 @Ilkj3$%/hd9#$'

# test()