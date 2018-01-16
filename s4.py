import random

from helpers import *

def c25():
    plaintext = base64_decode_file('25.txt')
    rand_key = random_bytes(16)
    # Assuming that the nonce is 0 or know, otherwise I don't see how this is possible.
    nonce = 0
    ciphertext = ctr(plaintext, rand_key, nonce)
    # Because we're using CTR we can just use the ciphertext as the new edit to
    # recover the plaintext.
    return plaintext == edit(ciphertext, rand_key, 0, 0, ciphertext)

def c26():
    rand_key = random_bytes(16)
    prefix = 'comment1=cooking%20MCs;userdata='
    suffix = ';comment2=%20like%20a%20pound%20of%20bacon'
    def append_prepend(s):
        s = s.replace(';', '";"').replace('=', '"="')
        s = prefix + s + suffix
        return ctr(bytearray(s), rand_key, 0)

    def decrypt_and_find_admin(encrypted):
        plaintext = ctr(encrypted, rand_key, 0)
        return plaintext.find(';admin=true;') >= 0

    input_text = 'blah'
    plaintext = bytearray(prefix + input_text + suffix)
    ciphertext = append_prepend(input_text)
    target_block = bytearray(';admin=true;') + bytearray([0]*4)
    index = 3
    ciphertext[index*16:(index+1)*16] = xor(target_block, xor(plaintext[index*16:(index+1)*16], ciphertext[index*16:(index+1)*16]))
    return decrypt_and_find_admin(ciphertext)
 
def c27():
    bs = 16
    rand_key = random_bytes(bs)
    i_vector = rand_key
    def encrypt(pt):
        assert all([c > 32 for c in pt])
        return cbc_encrypt(pt, rand_key, i_vector, False)

    def decrypt(ct):
        pt = cbc_decrypt(ct, rand_key, i_vector, False)
        if all([c > 32 for c in pt]):
            return 'ok', pt
        else:
            return 'error', pt

    pt = bytearray([ord('A')] * bs * 3)
    ct = encrypt(pt)
    c_blocks = split_into_blocks(ct, bs)
    ct = c_blocks[0] + bytearray([0]*bs) + c_blocks[0]
    res = decrypt(ct)
    if res[0] == 'error':
        p_blocks = split_into_blocks(res[1], bs)
        return rand_key == xor(p_blocks[0], p_blocks[2])
        
def c28():
    key = random_bytes(16)
    return mac('aoeuhtns', key)




    
