import base64

from helpers import *

def c9():
    return pkcs7_pad(bytearray(b'YELLOW SUBMARINE'), 20)

def c10():
    ciphertext = base64_decode_file('10.txt')
    key = bytearray(b'YELLOW SUBMARINE')
    return cbc_decrypt(ciphertext, key, bytearray([0] * len(key)))

def c12():
    rand_key = random_bytes(16)
    s = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    plaintext = bytearray(base64.b64decode(s))
    encrypted = encrypt_aes_ecb(plaintext, rand_key, True)

    # Find the block size.
    # Go up to 256 bit blocks.
    block_size = 0
    for i in range(2, 33):
        encrypted_with_prefix = encrypt_aes_ecb(bytearray([ord('A')] * i) + plaintext, rand_key, True)
        if encrypted[:i] == encrypted_with_prefix[i:2*i]:
            block_size = i
            break

    # Detect ECB by appending two identical blocks
    encrypted_double_prefix = encrypt_aes_ecb(bytearray([ord('A')] * 2 * block_size) + plaintext, rand_key, True)
    print 'key length:', block_size, 'is ECB:', encrypted_double_prefix[:i] == encrypted_double_prefix[i:2*i]

    decrypted = []
    for i in range(len(encrypted)):
        num_bytes_append = block_size - (i % block_size) - 1
        ii = i + num_bytes_append + 1
        for j in range(256):
            encrypted_block = encrypt_aes_ecb(bytearray([ord('A')] * num_bytes_append) + plaintext, rand_key, True)[ii-block_size:ii]
            encrypted_candidate_block = encrypt_aes_ecb(bytearray(([ord('A')] * num_bytes_append) + decrypted + [j]) + plaintext, rand_key, True)[ii-block_size:ii]
            if encrypted_block == encrypted_candidate_block:
                decrypted.append(j)
                break

    return pkcs7_unpad(bytearray(decrypted))

def c13():
    rand_key = random_bytes(16)

    def profile_for(email):
        o = [('email', email.strip('&').strip('=')),('uid', 10), ('role', 'user')]
        return '&'.join('{0}={1}'.format(pair[0], pair[1]) for pair in o)

    def encrypt_profile(email):
        return encrypt_aes_ecb(bytearray(profile_for(email)), rand_key)

    def decrypt_parse(encrypted_profile):
        return pkcs7_unpad(decrypt_aes_ecb(encrypted_profile, rand_key)).decode()

    p1 = encrypt_profile('foo@bar.coadmin')
    p2 = encrypt_profile('foo@bar.commm')
    return decrypt_parse(p2[0:32]+p1[16:32])

# TODO: make this actually work.
def c14():
    rand_key = random_bytes(16)
    plaintext = bytearray(b'babar')

    def oracle(attack_ba):
        rand_bytes = random_bytes(random.randint(1, 200))
        return encrypt_aes_ecb(rand_bytes + attack_ba + plaintext, rand_key, True), [rand_bytes, attack_ba, plaintext]

    # Find the block size.
    # Go up to 256 bit blocks.
    for i in range(2, 33):
        encrypted = oracle(bytearray([ord('A')] * 4 * i))[0]
        repeat = find_longest_repeat(encrypted, i)
        if repeat['count'] > 1:
            block_size = i
            break

    decrypted = []
    while True:
        prefix = bytearray()
        if len(decrypted) < block_size - 1:
            prefix = bytearray([ord('A')] * (block_size - len(decrypted) - 1))

        table = build_lookup_table(prefix + bytearray(decrypted[-block_size+1:]), oracle, block_size)

        # Wait until you get a random string which is a multiple of 16
        b = None
        while b == None:
            encrypted, full_string = oracle(prefix)
            chunks = [encrypted[j:j+block_size] for j in range(0, len(encrypted), block_size)]
            for chunk in chunks:
                if str(chunk) in table:
                    b = table[str(chunk)]
                    decrypted.append(b)
                    print 'decrypted', full_string, bytearray(decrypted)
                    break

def c15():
    print pkcs7_is_padded(bytearray(b'ICE ICE BABY\x04\x04\x04\x04'))
    print pkcs7_is_padded(bytearray(b'ICE ICE BABY\x05\x05\x05\x05'))
    print pkcs7_is_padded(bytearray(b'ICE ICE BABY\x01\x02\x03\x04'))

def c16():
    block_size = 16
    rand_key = random_bytes(block_size)
    i_vector = random_bytes(block_size)
    prefix = 'comment1=cooking%20MCs;userdata='
    suffix = ';comment2=%20like%20a%20pound%20of%20bacon'
    def append_prepend(s):
        s = s.replace(';', '";"').replace('=', '"="')
        s = prefix + s + suffix
        return cbc_encrypt(bytearray(s), rand_key, i_vector)

    def decrypt_and_find_admin(encrypted):
        plaintext = pkcs7_unpad(cbc_decrypt(encrypted, rand_key, i_vector))
        return plaintext.find(';admin=true;') >= 0

    input_text = 'blah'
    plaintext = bytearray(prefix + input_text + suffix)
    ciphertext = append_prepend(input_text)
    # We want to set the 4rd block to target_block, so we'll work on the third block.
    index = 3
    target_block = pkcs7_pad(bytearray(';admin=true;'), block_size)
    p_blocks = [plaintext[i:i+block_size] for i in range(0, len(plaintext), block_size)]
    c_blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    c_blocks[index-1] = xor(target_block, xor(p_blocks[index], c_blocks[index-1]))
    new_ciphertext = bytearray([b for block in c_blocks for b in block])
    return decrypt_and_find_admin(new_ciphertext)

