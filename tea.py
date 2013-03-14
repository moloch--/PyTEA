#!/usr/bin/env python
#################################################################################
# Python implementation of the Tiny Encryption Algorithm (TEA)
# By Moloch
#
# About: TEA has a few weaknesses. Most notably, it suffers from 
#        equivalent keys—each key is equivalent to three others, 
#        which means that the effective key size is only 126 bits. 
#        As a result, TEA is especially bad as a cryptographic hash 
#        function. This weakness led to a method for hacking Microsoft's
#        Xbox game console (where I first encountered it), where the 
#        cipher was used as a hash function. TEA is also susceptible 
#        to a related-key attack which requires 2^23 chosen plaintexts 
#        under a related-key pair, with 2^32 time complexity.
# 
#        Block size: 64bits
#          Key size: 128bits
#
##################################################################################


import getpass

from hashlib import sha256
from ctypes import c_uint32

### Magical Constants
DELTA = 0x9e3779b9
SUMATION = 0xc6ef3720
ROUNDS = 32
BLOCK_SIZE = 2  # number of 32-bit ints
KEY_SIZE = 4 


### Functions ###
def encrypt_block(block, key, verbose=False):
    ''' 
    Encrypt a single 64-bit block using a given key 
    @param block: list of two c_uint32s
    @param key: list of four c_uint32s
    '''
    assert len(block) == BLOCK_SIZE
    assert len(key) == KEY_SIZE
    sumation = c_uint32(0)
    delta = c_uint32(DELTA)
    for index in range(0, ROUNDS):
        sumation.value += delta.value
        block[0].value += ((block[1].value << 4) + key[0].value) ^ (block[1].value + sumation.value) ^ ((block[1].value >> 5) + key[1].value)
        block[1].value += ((block[0].value << 4) + key[2].value) ^ (block[0].value + sumation.value) ^ ((block[0].value >> 5) + key[3].value)
        if verbose: print "\t--> Encrypting block round %d of %d" % (index, ROUNDS)
    return block

def decrypt_block(block, key, verbose=False):
    ''' 
    Decrypt a single 64-bit block using a given key 
    @param block: list of two c_uint32s
    @param key: list of four c_uint32s
    '''
    assert len(block) == BLOCK_SIZE
    assert len(key) == KEY_SIZE
    sumation = c_uint32(SUMATION)
    delta = c_uint32(DELTA)
    for index in range(0, ROUNDS):
        block[1].value -= ((block[0].value << 4) + key[2].value) ^ (block[0].value + sumation.value) ^ ((block[0].value >> 5) + key[3].value);
        block[0].value -= ((block[1].value << 4) + key[0].value) ^ (block[1].value + sumation.value) ^ ((block[1].value >> 5) + key[1].value);
        sumation.value -= delta.value
        if verbose: print "\t<-- Decrypting block round %d of %d" % (index, ROUNDS)
    return block

def to_c_array(data):
    ''' Converts a string to a list of c_uint32s '''
    c_array = []
    char_array = [hex(ord(char))[2:] for char in data]
    for index in range(0, len(char_array), 4):
        block = char_array[index:index + 4]
        hex_value = '0x' + ''.join(block)
        c_array.append(c_uint32(int(hex_value, 16)))
    return c_array

def to_string(c_array):
    ''' Converts a list of c_uint32s to a Python (ascii) string '''
    output = ''
    for block in c_array:
        hex_string = hex(block.value)[2:-1]
        if len(hex_string) != 8: 
            hex_string = "0"+hex_string
        for index in range(0, len(hex_string), 2):
            byte = int('0x%02s' % hex_string[index:index + 2], 16)
            output += chr(byte)
    return output

def encrypt(data, key, verbose=False):
    '''
    Encrypt string using TEA algorithm with a given key
    '''
    data = to_c_array(data)
    key = to_c_array(key.encode('ascii', 'ignore'))
    cipher_text = []
    for index in range(0, len(data), 2):
        block = data[index:index + 2]
        part1, part2 = encrypt_block(block, key)
        cipher_text.append(part1)
        cipher_text.append(part2)
        if verbose: print "[*] Encrypting block %d" % index
    return to_string(cipher_text)

def decrypt(data, key, verbose=False):
    data = to_c_array(data)
    key = to_c_array(key.encode('ascii', 'ignore'))
    plain_text = []
    for index in range(0, len(data), 2):
        block = data[index:index + 2]
        decrypted_block = decrypt_block(block, key)
        for uint in decrypted_block:
            plain_text.append(uint)
        if verbose: print "[*] Encrypting block %d" % index
    return to_string(plain_text)

def get_key():
    ''' Generate a key based on user password '''
    password = getpass.getpass("[?] Password: ")
    sha = sha256()
    sha.update(password + "Magic Static Salt")
    sha.update(sha.hexdigest())
    return ''.join([char for char in sha.hexdigest()[::4]])

def encrypt_file(fpath, key, verbose=False):
    key = get_key()
    with open(fpath, 'r+') as fp:
        data = fp.read()
        cipher_text = encrypt(data)
        fp.seek(0)
        fp.write(cipher_text)
    fp.close()

def decrypt_file(fpath, key, verbose=False):
    key = get_key()
    with open(fpath, 'r+') as fp:
        data = fp.read()
        plain_text = decrypt(data)
        fp.seek(0)
        fp.write(plain_text)
    fp.close()

### UI Code ###
if __name__ == '__main__':
    import argparse
    data = "12341234"
    key = get_key()
    print 'key (%d): %s' % (len(key), key)
    print 'start:', data
    cipher_text = encrypt(data, key)
    print 'encrypted:', cipher_text
    print 'decrypted:', decrypt(cipher_text, key)


