from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import sys

blockSize = 16
def main():

    key = get_random_bytes(16) # 16 bytes for AES-128
    """ we will be using the ECB mode in our AES cipher for both mode 
    implementations so that we aren't using the built-in mode for our CBC 
    method """
    cipher = AES.new(key, AES.MODE_ECB) 
    filename = sys.argv[1]

    with open (filename, 'r') as f:
        key = b'Sixteen byte key'
        cipher = AES.new(key, AES.MODE_ECB)
        
        ecb_mode(f, cipher)
        cbc_mode(f, cipher)

def ecb_mode(file, cipher):
    with open ("encryption_ecb", "wb") as w:
        block = file.read(blockSize)
        while len(block) == blockSize:
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(block)
            w.write(ciphertext)
            block = file.read(blockSize)
        bytes_to_add = blockSize - len(block)
        # w.write(block)
        # for i in range (bytes_to_add):
        #     w.write(bytes([0]))
        
        
def cbc_mode(file, cipher):
    with open ("encryption_cbc", "wb") as w:
        block = file.read(16)
        
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(block)
        w.write(ciphertext)

if __name__ == '__main__':
    main()
