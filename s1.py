import base64
import itertools

from helpers import *

def c1():
    ba = bytearray.fromhex('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    return base64.b64encode(ba)

def c2():
    ba1 = bytearray.fromhex('1c0111001f010100061a024b53535009181c')
    ba2 = bytearray.fromhex('686974207468652062756c6c277320657965')
    ba = bytearray([bb1 ^ bb2 for bb1, bb2 in zip(ba1, ba2)])
    return ba.hex()

def c3():
    ba = bytearray.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    return find_best_key(xor_with_all_chars(ba))

def c4():
    bas = []
    with open('4.txt') as f:
        for line in f.readlines():
            bas.append(bytearray.fromhex(line.strip()))

    smallest_distance = 10000
    best_line = None
    best_char = None
    for ba in bas:
        current_char, current_distance = find_best_key(xor_with_all_chars(ba))
        if current_distance < smallest_distance:
            smallest_distance = current_distance
            best_char = current_char
            best_line = ba
    return xor_with_char(best_line, best_char)

def c5():
    ba = bytearray(b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
    return repeating_xor_with(ba, bytearray(b'ICE')).hex()

def c6():
    ciphertext = bytearray(base64_decode_file('6.txt'))
    key_size = guess_key_size_repeating_xor(ciphertext)
    return break_repeating_xor(ciphertext, key_size)

def c7():
    ciphertext = base64_decode_file('7.txt')
    key = b'YELLOW SUBMARINE'
    return decrypt_aes_ecb(ciphertext, key)
