import base64
import itertools
import random
import math
from collections import defaultdict
from struct import pack, unpack

# pip install pycrypto
from Crypto.Cipher import AES

def xor_with_char(ba, c):
    return bytearray([b1 ^ c for b1 in ba])

def xor_with_all_chars(ba):
    uncoded = {}
    for c in range(127):
        uncoded[c] = xor_with_char(ba, c)
    return uncoded

english_ref = {b'e':12.70,b't':9.06,b'a':8.17,b'o':7.51,b'i':6.97,b'n':6.75,b's':6.33,b'h':6.09,b'r':5.99,b'd':4.25,b'l':4.03,b'c':2.78,b'u':2.76,b'm':2.41,b'w':2.36,b'f':2.23,b'g':2.02,b'y':1.97,b'p':1.93,b'b':1.29,b'v':0.98,b'k':0.77,b'j':0.15,b'x':0.15,b'q':0.10,b'z':0.07}
def english_distance(s):
    return sum([abs(100*float(s.count(l))/len(s) - english_ref[l]) for l in english_ref])

def find_best_key(candidates):
    smallest_distance = 10000
    best_key = None
    for key in candidates.keys():
        current_distance = english_distance(candidates[key])
        if current_distance < smallest_distance:
            smallest_distance = current_distance
            best_key = key
    return best_key, smallest_distance

def repeating_xor_with(ba, key):
    return bytearray([b1 ^ b2 for b1, b2 in zip(ba, itertools.cycle(key))])

def hamming_distance(ba1, ba2):
    return sum([format(b1 ^ b2, 'b').count('1') for b1, b2 in zip(ba1, ba2)])

def guess_key_size_repeating_xor(ciphertext):
    smallest_distance = 100000
    best_size = 0
    for key_size in range(2, 41):
        blocks = []
        # Look at the first 4 key_size blocks.
        first_bytes = ciphertext[:(4*key_size)]
        for i in range(4):
            ba = bytearray()
            for j in range(key_size):
                ba.append(first_bytes.pop(0))
            blocks.append(ba)

        pairs = [(ba1, ba2) for ba1 in blocks for ba2 in blocks if ba1 != ba2]
        sum_distances = sum([float(hamming_distance(ba1, ba2)) / key_size for ba1, ba2 in pairs])
        avg_distance = float(sum_distances) / len(pairs)

        if avg_distance < smallest_distance:
            smallest_distance = avg_distance
            best_size = key_size

    return best_size

def break_repeating_xor(ciphertext, key_size):
    blocks = []
    for i in range(0, len(ciphertext), key_size):
        if i + key_size <= len(ciphertext):
            blocks.append(ciphertext[i:i + key_size])

    # Transposing blocks.
    blocks_t = []
    for i in range(key_size):
        blocks_t.append([block[i] for block in blocks])

    key = bytearray()
    for block in blocks_t:
        key.append(find_best_key(xor_with_all_chars(block))[0])

    return repeating_xor_with(ciphertext, key), key

def base64_decode_file(file_name):
    with open(file_name) as f:
        return base64.b64decode(f.read().replace('\n', ''))

def pkcs7_pad(ba, block_length):
    bytes_to_pad = block_length - (len(ba) % block_length)
    return ba + bytearray([bytes_to_pad] * bytes_to_pad)

def pkcs7_is_padded(ba):
    padding = ba[-ba[-1]:]
    return all([padding[b] == len(padding) for b in range(0, len(padding))])

def pkcs7_unpad(ba):
    assert pkcs7_is_padded(ba)
    return ba[:-ba[-1]]

def xor(ba1, ba2):
    return bytearray([b1 ^ b2 for b1, b2 in zip(ba1, ba2)])

def encrypt_aes_ecb(plaintext, key, pad=False):
    cipher = AES.new(key)
    if pad:
        return bytearray(cipher.encrypt(pkcs7_pad(plaintext, len(key))))
    else:
        return bytearray(cipher.encrypt(plaintext))

def decrypt_aes_ecb(ciphertext, key):
    cipher = AES.new(key)
    return bytearray(cipher.decrypt(ciphertext))

# This should have a constant block size of 16 and not depend on the key size.
def cbc_encrypt(plaintext, key, i_vector, pad=True):
    key_size = len(key)
    padded_text = plaintext
    if pad:
        padded_text = pkcs7_pad(plaintext, key_size)
    output = bytearray()
    prev_block = i_vector
    for i in range(0, len(padded_text), key_size):
        xored_with_prev = xor(prev_block, padded_text[i:i + key_size])
        crypted_block = encrypt_aes_ecb(xored_with_prev, key)
        output += crypted_block
        prev_block = crypted_block
    return output

# This should have a constant block size of 16 and not depend on the key size.
def cbc_decrypt(ciphertext, key, i_vector, unpad=True):
    key_size = len(key)
    output = bytearray()
    prev_block = i_vector
    for i in range(0, len(ciphertext), key_size):
        decrypted_block = decrypt_aes_ecb(ciphertext[i:i + key_size], key)
        xored_with_prev = xor(decrypted_block, prev_block)
        output += xored_with_prev
        prev_block = ciphertext[i:i + key_size]
    if unpad:
        return pkcs7_unpad(output)
    else:
        return output

def random_bytes(size):
    return bytearray([random.randint(0, 255) for i in range(size)])

def encryption_oracle(plaintext):
    key = random_bytes(16)
    plaintext = random_bytes(random.randint(5,11)) + plaintext + random_bytes(random.randint(5,11))
    coin_flip = bool(random.randint(0, 1))
    if coin_flip:
        i_vector = random_bytes(16)
        return cbc_encrypt(plaintext, key, i_vector)
    else:
        return encrypt_aes_ecb(pkcs7_pad(plaintext, len(key)), key)

def ecb_or_cbc(ciphertext):
    # AES, so 16 byte block size is good.
    block_size = 16
    num_blocks = len(ciphertext) / block_size
    unique_blocks = set()
    for i in range(0, len(ciphertext), block_size):
        unique_blocks.add(str(ciphertext[i: i + block_size]))
    if len(unique_blocks) < num_blocks:
        return 'ecb'
    else:
        return 'cbc'

def parse_kv(s):
    res = {}
    pairs = s.split('&')
    for p in pairs:
        [k, v] = p.split('=')
        res[k] = v
    return res

def find_longest_repeat(data, block_size):
    chunks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    prev = None
    count = 1
    max_result = {'index': None, 'chunk': None, 'count': 0}
    for i in range(len(chunks)):
        chunk = chunks[i]
        if chunk == prev:
            count += 1
        else:
            count = 1
        if count > max_result['count']:
            max_result = {'chunk': chunk, 'count': count, 'index': i}
        prev = chunk
    return max_result

def build_lookup_table(prefix, oracle, block_size):
    num_repeats = 8
    byte_for_chunk = {}
    for j in range(256):
        encrypted = oracle((prefix + bytearray([j])) * num_repeats)[0]
        repeat = find_longest_repeat(encrypted, block_size)
        if repeat['count'] >= num_repeats - 2:
            byte_for_chunk[str(repeat['chunk'])] = j
        else:
            raise Exception('Did not find repeating sequence.')

    return byte_for_chunk

def split_into_blocks(ba, block_size):
    return [ba[i:i+block_size] for i in range(0, len(ba), block_size)]

def little_endian(n, size):
    # Convert to real hex.
    hex_n = hex(n)[2:]
    if len(hex_n) % 2 ==1:
        hex_n = '0' + hex_n
    ba = bytearray.fromhex(hex_n)
    return bytearray(reversed(ba)) + bytearray([0] * (size-len(ba)))

def ctr(text, key, nonce):
    block_size = 16
    nonce_ba = little_endian(nonce, 8)
    counter = 0
    c_blocks = split_into_blocks(text, block_size)
    decrypted = bytearray()
    for i in range(len(c_blocks)):
        counter_ba = little_endian(counter, 8)
        stream = encrypt_aes_ecb(nonce_ba+counter_ba, key)
        decrypted += xor(c_blocks[i], stream[:len(c_blocks[i])])
        counter += 1
    return decrypted

def int32(x):
    # Get the 32 least significant bits.
    return int(0xFFFFFFFF & x)

class MT19937:
    n = 624

    def __init__(self, seed):
        self.index = self.n
        self.mt = [0] * self.n
        self.mt[0] = seed
        for i in range(1, self.index):
            self.mt[i] = int32(1812433253 * (self.mt[i-1] ^ self.mt[i-1] >> 30) + i)

    def get_number(self):
        if self.index >= self.n:
            self.twist()

        y = self.mt[self.index]

        y = y ^ (y >> 11)
        y = y ^ ((y << 7) & 2636928640)
        y = y ^ ((y << 15) & 4022730752)
        y = y ^ (y >> 18)

        self.index = self.index + 1
        return int32(y)

    def twist(self):
        for i in range(self.n):
            # Get the most significant bit and add it to the less significant
            # bits of the next number
            y = int32((self.mt[i] & 0x80000000) + (self.mt[(i+1) % self.n] & 0x7fffffff))
            self.mt[i] = self.mt[(i+397) % self.n] ^ y >> 1
            if y % 2 != 0:
                self.mt[i] = self.mt[i] ^ 0x9908b0df

        self.index = 0

    def inverse(self, y):
        y = y ^ (y >> 18)
        y = y ^ ((y << 15) & 4022730752)

        mask = 2636928640
        a = y << 7
        b = y ^ (a & mask)
        c = b << 7
        d = y ^ (c & mask)
        e = d << 7
        f = y ^ (e & mask)
        g = f << 7
        h = y ^ (g & mask)
        i = h << 7
        k = y ^ (i & mask)
        y = k

        a = y >> 11
        b = y ^ a
        c = b >> 11
        return (y ^ c)

    def splice_state(self, mt_new):
        self.mt = mt_new

class Mersenne_stream:
    def __init__(self, seed):
        self.m = MT19937(seed)
        self.current_bytes = bytearray()

    def get_byte(self):
        if len(self.current_bytes) == 0:
            # Convert int to a byte array in big endian encoding.
            self.current_bytes = [hex(self.m.get_number() >> i & 0xff) for i in (24,16,8,0)]
        return int(self.current_bytes.pop(), 16)

def mersenne_cipher(text, key):
    int_key = bytes_to_int(key)
    m_stream = Mersenne_stream(int_key)
    decrypted = bytearray()
    for i in range(len(text)):
        decrypted.append(text[i] ^ m_stream.get_byte())
    return decrypted

# Big Endian encoding.
def bytes_to_int(ba):
    return int(str(ba).encode('hex'), 16)

# Big Endian encoding.
def int_to_bytes(n):
    return bytearray([int(hex(n >> i & 0xff), 16) for i in (24,16,8,0)])

def edit(ciphertext, key, nonce, offset, newtext):
    block_size = 16
    nonce_ba = little_endian(nonce, 8)
    # Since this is "seek and edit", let's optimize a bit and only generate
    # the necessary parts of the keystream.
    start_index = block_size * (offset / block_size)
    rem_offset = offset % block_size
    end_index = block_size * int(math.ceil(float(offset + len(newtext)) / block_size))

    encrypted = bytearray()
    counter = start_index / block_size
    for i in range(start_index, end_index, block_size):
        counter_ba = little_endian(counter, 8)
        stream = encrypt_aes_ecb(nonce_ba+counter_ba, key)
        encrypted += xor(newtext[i:i+block_size], stream[rem_offset:rem_offset+len(newtext[i:i+block_size])])
        counter += 1

    return ciphertext[:offset] + encrypted + ciphertext[offset+len(newtext):]

def sha1(data):
    """ Returns the SHA1 sum as a 40-character hex string """
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    def rol(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff

    # After the data, append a '1' bit, then pad data to a multiple of 64 bytes
    # (512 bits).  The last 64 bits must contain the length of the original
    # string in bits, so leave room for that (adding a whole padding block if
    # necessary).
    padding = chr(128) + chr(0) * (55 - len(data) % 64)
    if len(data) % 64 > 55:
        padding += chr(0) * (64 + 55 - len(data) % 64)
    padded_data = data + padding + pack('>Q', 8 * len(data))

    thunks = [padded_data[i:i+64] for i in range(0, len(padded_data), 64)]
    for thunk in thunks:
        w = list(unpack('>16L', thunk)) + [0] * 64
        for i in range(16, 80):
            w[i] = rol((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1)

        a, b, c, d, e = h0, h1, h2, h3, h4

        # Main loop
        for i in range(0, 80):
            if 0 <= i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i < 80:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = rol(a, 5) + f + e + k + w[i] & 0xffffffff, \
                            a, rol(b, 30), c, d

        h0 = h0 + a & 0xffffffff
        h1 = h1 + b & 0xffffffff
        h2 = h2 + c & 0xffffffff
        h3 = h3 + d & 0xffffffff
        h4 = h4 + e & 0xffffffff

    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

def mac(msg, key):
    return sha1(key + msg)


