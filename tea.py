#!/usr/bin/env python
##############################################################
# Python implementation of the Tiny Encryption Algorithm
# By Moloch
# 
#  Block size: 64bits
#    Key size: 128bits
##############################################################

from ctypes import c_uint32

### Magical Constants
DELTA = 0x9e3779b9
SUMATION = 0xc6ef3720
ROUNDS = 32
BLOCK_SIZE = 4 # Bytes


### Functions ###
def encrypt_block(block, key, verbose=False):
    ''' 
    Encrypt a single 64-bit block using a given key 
    @param block: list of two c_uint32s
    @param key: list of four c_uint32s
    '''
    assert len(block) == 2
    assert len(key) == 4
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
    assert len(block) == 2
    assert len(key) == 4
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
        #print 'hex block:', hex_string
        for index in range(0, len(hex_string), 2):
            #print 'Char:', '0x%02s' % hex_string[index:index + 2]
            byte = int('0x%02s' % hex_string[index:index + 2], 16)
            output += chr(byte)
    return output

def encrypt(data, key, verbose=False):
    '''
    Encrypt string using TEA algorithm with a given key
    '''
    assert isinstance(data, str)
    assert isinstance(key, str)
    data = to_c_array(data)
    key = to_c_array(key)
    cipher_text = []
    for index in range(0, len(data), 2):
        block = data[index:index + 2]
        part1, part2 = encrypt_block(block, key)
        cipher_text.append(part1)
        cipher_text.append(part2)
        if verbose: print "[*] Encrypting block %d" % index
    return to_string(cipher_text)

def decrypt(data, key, verbose=False):
    assert isinstance(data, str)
    assert isinstance(key, str)
    data = to_c_array(data)
    key = to_c_array(key)
    plain_text = []
    for index in range(0, len(data), 2):
        block = data[index:index + 2]
        decrypted_block = decrypt_block(block, key)
        for uint in decrypted_block:
            plain_text.append(uint)
        if verbose: print "[*] Encrypting block %d" % index
    return to_string(plain_text)


### UI Code ###
if __name__ == '__main__':
    data = "12341234"
    key = "asdfasdfasdfasdf"
    print 'start:', data
    cipher_text = encrypt(data, key)
    print 'encrypted:', cipher_text
    print 'decrypted:', decrypt(cipher_text, key)


