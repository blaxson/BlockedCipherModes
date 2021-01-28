from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import sys
import os

BLOCKSIZE = 16

def main():
    if len(sys.argv) != 2:
        print("usage: python3 AESencryption.py file", file=sys.stderr)
        return 1
    filename = sys.argv[1]
    try:
        fh = open(filename, 'rb')
    except FileNotFoundError:
        print("provide a file that already exists", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print("file not readable", file=sys.stderr)
        sys.exit(1)

    # set up cipher to be used
    #key = get_random_bytes(16) # 16 bytes for AES-128
    key = b'Sixteen byte key'
    cipher = AES.new(key, AES.MODE_ECB)
    
    # set up files to write to
    ecb_file = open("ECB_" + filename, "wb")
    cbc_file = open("CBC_" + filename, "wb")

    # handle case of .bmp file
    if filename.endswith(".bmp"):
        bmp_header = fh.read(54) # header is 54 bytes
        ecb_file.write(bmp_header)
        cbc_file.write(bmp_header)
        start_position = fh.tell() # save start position of pointer after bmp header
    else:
        start_position = 0

    # encrypt using ecb mode
    ecb_encrypt(fh, ecb_file, cipher)
    
    fh.seek(start_position) # reset pointer to beginning of encryption point

    # setup iv and encrypt using cbc mode
    iv_list = [41, 21, 44, 78, 121, 11, 1, 34, 2, 56, 111, 108, 34, 29, 90, 34]
    iv = bytearray(iv_list)
    cbc_encrypt(fh, cbc_file, cipher, iv)

    # close files
    fh.close()
    ecb_file.close()
    cbc_file.close()

def ecb_encrypt(r_file, w_file, cipher):
    block = get_next_block(r_file)
    while block != -1:
        ciphertext = cipher.encrypt(block)
        w_file.write(ciphertext)
        block = get_next_block(r_file)

def cbc_encrypt(r_file, w_file, cipher, iv):
    prev_block = iv
    next_block = get_next_block(r_file)
    while next_block != -1:
        block = xor_blocks(prev_block, next_block) #xor prev ciphertext with curr plaintext
        ciphertext = cipher.encrypt(block)
        w_file.write(ciphertext)
        prev_block = ciphertext
        next_block = get_next_block(r_file)

""" takes in two blocks, returns the exlusive or (XOR) of the two blocks """
def xor_blocks(block1, block2):
    xor_block = bytearray(BLOCKSIZE)
    for i in range(BLOCKSIZE):
        xor_block[i] = block1[i] ^ block2[i]
    return xor_block

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
