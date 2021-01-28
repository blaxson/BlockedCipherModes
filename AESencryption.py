from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import sys
import os

BLOCKSIZE = 16
"""
def main():

    filename = sys.argv[1]
    with open (filename, 'r') as f:
        key = get_random_bytes(16) # 16 bytes for AES-128
        cipher = AES.new(key, AES.MODE_ECB)
        
        ecb_mode(f, cipher)
        cbc_mode(f, cipher)

def ecb_mode(fh, cipher):
    with open ("encryption_ecb", "wb") as w:
        block = bytearray(16) # initialize block to 16 byte block of zeros
        temp = fh.read(BLOCKSIZE)
        while len(block) == BLOCKSIZE:
            ciphertext, tag = cipher.encrypt_and_digest(block)
            w.write(ciphertext)
            block = bytearray(16) # reinitialize
            temp = fh.read(BLOCKSIZE)

        bytes_to_add = BLOCKSIZE - len(block)
        # w.write(block)
        # for i in range (bytes_to_add):
        #     w.write(bytes([0]))
        
        
def cbc_mode(fh, cipher):
    with open ("encryption_cbc", "wb") as w:
        temp = fh.read(16)
        block = bytearray(16)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(block)
        w.write(ciphertext)

def get_next_block(fh):
    block = bytearray(16)
    temp = list(fh.read(BLOCKSIZE))
    block[:len(temp)] = temp
    return block
"""
####################################################

def main():
    if len(sys.argv) != 2:
        print("usage: python3 AESencryption.py filename", file=sys.stderr)
        return 1
    filename = sys.argv[1]
    try:
        fh = open(filename, 'rb')
    except FileNotFoundError:
        print("provide a file that already exists", file=sys.stderr)
    except PermissionError:
        print("file not readable", file=sys.stderr)
    
    #key = get_random_bytes(16) # 16 bytes for AES-128
    key = b'Sixteen byte key'
    cipher = AES.new(key, AES.MODE_ECB)
    
    ecb_encrypt(fh, cipher)
    fh.seek(0) # reset file handler to point to beginning of file
    cbc_encrypt(fh, cipher)

    fh.close()

def ecb_encrypt(file, cipher):
    ecb_file = open(file.name + ".ecb", "wb")   
    block = get_next_block(file)
    while block != -1:
        ciphertext = cipher.encrypt(block)
        ecb_file.write(ciphertext)
        block = get_next_block(file)
    ecb_file.close()

def cbc_encrypt(file, cipher, iv):
    cbc_file = open(file.name + ".cbc", "wb")
    prev_block = iv
    next_block = get_next_block(file)
    while block != -1:


""" takes in two blocks, returns the exlusive or (XOR) of the two blocks """
def xor_blocks(block1, block2)


""" takes in file handler and returns the next block to be encrypted from that
    file. Pads block if not an even block """
def get_next_block(fh):
    block = bytearray(BLOCKSIZE) # initialize block to 16 byte block of zeros
    temp = list(fh.read(BLOCKSIZE)) # convert str to list to be put in bytearray
    if len(temp) == 0: # if end of file reached, return -1
        return -1
    block[:len(temp)] = temp
    return block

if __name__ == '__main__':
    main()
