#!/usr/bin/env python
#################################################################################
# Python implementation of the Tiny Encryption Algorithm (TEA)
# By Moloch
#
# About: TEA has a few weaknesses. Most notably, it suffers from 
#        equivalent keys each key is equivalent to three others, 
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


import os
import getpass
import platform

from hashlib import sha256
from ctypes import c_uint32

if platform.system().lower() in ['linux', 'darwin']:
    INFO = "\033[1m\033[36m[*]\033[0m "
    WARN = "\033[1m\033[31m[!]\033[0m "
else:
    INFO = "[*] "
    WARN = "[!] "

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
        if verbose: print("\t--> Encrypting block round %d of %d" % (index + 1, ROUNDS))
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
        if verbose: print("\t<-- Decrypting block round %d of %d" % (index + 1, ROUNDS))
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
        if verbose: 
            print(INFO + "Encrypting block %d" % index)
        block = data[index:index + 2]
        block = encrypt_block(block, key, verbose)
        for uint in block:
            cipher_text.append(uint)
    if verbose:
        print(INFO + "Encryption completed successfully")
    return to_string(cipher_text)

def decrypt(data, key, verbose=False):
    data = to_c_array(data)
    key = to_c_array(key.encode('ascii', 'ignore'))
    plain_text = []
    for index in range(0, len(data), 2):
        if verbose: 
            print(INFO + "Encrypting block %d" % index)
        block = data[index:index + 2]
        decrypted_block = decrypt_block(block, key, verbose)
        for uint in decrypted_block:
            plain_text.append(uint)
    if verbose:
        print(INFO + "Decryption compelted successfully")
    return to_string(plain_text)

def get_key(password=''):
    ''' Generate a key based on user password '''
    if 0 == len(password):
        password = getpass.getpass(INFO + "Password: ")
    sha = sha256()
    sha.update(password + "Magic Static Salt")
    sha.update(sha.hexdigest())
    return ''.join([char for char in sha.hexdigest()[::4]])

def encrypt_file(fpath, key, verbose=False):
    with open(fpath, 'r+') as fp:
        data = fp.read()[:-1]
        cipher_text = encrypt(data, key, verbose)
        fp.seek(0)
        fp.write(cipher_text)
    fp.close()

def decrypt_file(fpath, key, verbose=False):
    with open(fpath, 'r+') as fp:
        data = fp.read()[:-1]
        plain_text = decrypt(data, key, verbose)
        fp.seek(0)
        fp.write(plain_text)
    fp.close()

def pad_data(data):
    pad_delta = len(data) % BLOCK_SIZE
    print 'padding:', pad_delta
    return data

### UI Code ###
if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser(
        description='Python implementation of the TEA cipher',
    )
    parser.add_argument('-e', '--encrypt',
        help='encrypt a file',
        dest='epath',
        default=None
    )
    parser.add_argument('-d', '--decrypt',
        help='decrypt a file',
        dest='dpath',
        default=None
    )
    parser.add_argument('--verbose',
        help='display verbose output',
        default=False,
        action='store_true',
        dest='verbose'
    )
    args = parser.parse_args()
    if args.epath is None and args.dpath is None:
        print('Error: Must use --encrypt or --decrypt')
    elif args.epath is not None:
        print(WARN + 'Encrypt Mode: The file will be overwritten')
        if os.path.exists(args.epath) and os.path.isfile(args.epath):
            key = get_key()
            encrypt_file(args.epath, key, args.verbose)
        else:
            print(WARN + 'Error: target does not exist, or is not a file')
    elif args.dpath is not None:
        print(WARN + 'Decrypt Mode: The file will be overwritten')
        if os.path.exists(args.dpath) and os.path.isfile(args.dpath):
            key = get_key()
            decrypt_file(args.dpath, key, args.verbose)
        else:
            print(WARN + 'Error: target does not exist, or is not a file')


