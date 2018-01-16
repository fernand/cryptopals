import base64
import random
import itertools
import time

from helpers import *

def c17():
    strings = [
        b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
    ]

    block_size = 16
    rand_key = random_bytes(block_size)
    iv = random_bytes(block_size)

    def get_ciphertext_iv():
        index = random.randint(0, len(strings)-1)
        ba = bytearray(base64.b64decode(strings[index]))
        return cbc_encrypt(ba, rand_key, iv), iv

    def decrypt_and_check(ciphertext):
        plaintext = cbc_decrypt(ciphertext, rand_key, iv, False)
        return pkcs7_is_padded(plaintext)

    ciphertext = get_ciphertext_iv()[0]
    decrypted = bytearray()
    for i in range(len(ciphertext)):
        # Progressively remove later blocks as we decrypt more
        max_index = block_size * ((len(ciphertext) / block_size) - (i / block_size))
        pad_byte = 1 + i % block_size

        blocks = split_into_blocks(iv + ciphertext[:max_index], block_size)
        last_block = blocks.pop()
        prev_block = blocks.pop()
        # Get rid of the iv if it's not part of prev_block.
        prefix = bytearray(itertools.chain(blocks[1:-2]))

        for j in range(256):
            new_ciphertext = prefix + prev_block[:-pad_byte] + xor(
                bytearray([pad_byte]*pad_byte),
                xor(bytearray([j]) + decrypted[-i-1:max_index], prev_block[-pad_byte:])) + last_block
            if decrypt_and_check(new_ciphertext):
                decrypted = bytearray([j]) + decrypted

    # If the plaintext was padded, we'll end up with a \x01 at the end and then some padding.
    if decrypted[-1] == 1:
        decrypted.pop()
    return pkcs7_unpad(decrypted)

def c18():
    ciphertext = bytearray(base64.b64decode(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='))
    key = bytearray(b'YELLOW SUBMARINE')
    return ctr(ciphertext, key, 0)

# This doesn't work perfectly because break_repeating_xor could be improved.
# TODO: improve break_repeating_xor by using bi/tri-grams and other techniques.
def c20():
    strings = []
    with open('20.txt') as f:
        for line in f.readlines():
            strings.append(line.strip())
    plaintexts = [bytearray(base64.b64decode(s)) for s in strings]

    block_size = 16
    key = random_bytes(16)
    nonce = 0
    ciphertexts = [ctr(plaintext, key, nonce) for plaintext in plaintexts]
    smallest_len = min([len(ct) for ct in ciphertexts])

    ciphertext = bytearray([b for ct in ciphertexts for b in ct[:smallest_len]])
    return break_repeating_xor(ciphertext, smallest_len)

def c22():
    seed = int(time.time())
    m = MT19937(seed)
    target_number = m.get_number()
    # i simulates the ammount of seconds which have past since the target RNG was seeded.
    # We're thus assuming that it was seeded at most 300 seconds ago.
    t = int(time.time())
    time.sleep(random.randint(5,10))
    for i in range(300):
        t -= i
        r = MT19937(t)
        if r.get_number() == target_number:
            return t
        if i == 299:
            raise Exception('Seed not found')

def c23():
    seed = int(time.time())
    m = MT19937(seed)
    state = []
    for i in range(624):
        state.append(m.inverse(m.get_number()))

    m2 = MT19937(0)
    m2.splice_state(state)
    for i in range(10):
        print m.get_number(), m2.get_number()

def c24_a():
    key = random_bytes(2)
    suffix =  bytearray([ord('A')] * 14)
    plaintext = random_bytes(random.randint(1,30)) + suffix
    ciphertext = mersenne_cipher(plaintext, key)
    # Brute force the key
    for i in range(int('0xffff', 16)):
        target_pt = random_bytes(len(ciphertext) - 14) + suffix
        candidate_ct = mersenne_cipher(target_pt, int_to_bytes(i))
        if candidate_ct.find(ciphertext[-14:]) >= 0:
            return i

def c24_b():
    t = int(time.time())
    stream = Mersenne_stream(t)
    reset_token = bytearray([stream.get_byte() for i in range(64)])
    time.sleep(random.randint(1, 10))
    t = int(time.time())
    for i in range(300):
        t -= i
        candidate_stream = Mersenne_stream(t)
        candidate_token = bytearray([candidate_stream.get_byte() for i in range(64)])
        if candidate_token == reset_token:
            return t
