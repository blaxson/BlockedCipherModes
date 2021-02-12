from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import sys
import os
import io

from AESencryption import cbc_encrypt
from AESencryption import cbc_decrypt

def main():
    key_list = get_random_bytes(16) # 16 bytes for AES-128
    iv_list = get_random_bytes(16)
    iv = bytearray(iv_list)
    key = bytearray(key_list)
    cipher = AES.new(key, AES.MODE_ECB)

    cipher_string = submit(cipher, iv)
    print(verify(cipher_string, cipher, iv))
    

def submit(cipher, iv):    
    userid = 456
    sessionid = 31337
    usr_str = input("User Input: ")
    usr_str.replace('=', '%3D')
    usr_str.replace(';', '%3B')
    final_str = "userid={0};userdata={1};session-id={2}".format(userid, usr_str, sessionid)
    
    cipher_stream = io.BytesIO()
    readFileStream = io.BytesIO(bytes(final_str, 'utf-8'))

    cbc_encrypt(readFileStream, cipher_stream, cipher, iv)
    
    return cipher_stream.getvalue()

def verify(cipher_string, cipher, iv):
    pattern = ";admin=true;"
    
    cipher_text = io.BytesIO(cipher_string) #cipher_block
    plain_text_stream = io.BytesIO()
    cbc_decrypt(cipher_text, plain_text_stream, cipher, iv)
    plain_text = plain_text_stream.getvalue() # plain_text_block
    
    # start cbc byte flip attack
    encoded = pattern.encode('utf-8')
    desired_block = bytearray(encoded) # desired_block
    cipher_block = bytearray(cipher_string)

    cipher_block[0:16] = manipulate_cipher(cipher_block[0:16], plain_text[16:32], desired_block, 0)
 
    # decrypt cipher again, this time with the manipulated ciphertext
    new_cipher_text = io.BytesIO(bytes(cipher_block))
    new_plain_text_stream = io.BytesIO()
    cbc_decrypt(new_cipher_text, new_plain_text_stream, cipher, iv)


    new_plain_text = new_plain_text_stream.getvalue()
   
    # have to convert any 'plaintext' byte > 127 back to an ascii val.
    # this is the garbled decryption that we don't care about 
    new_plain_array = bytearray(new_plain_text)
    for i in range(0,16):
        new_plain_array[i] = new_plain_array[i] % 127
    # convert back into plaintext from bytes
    new_plain_text = bytes(new_plain_array).decode('utf-8')

    return pattern in new_plain_text

""" takes in the cipher block to overwrite, what your desired message is, and
an offset of where you want the desired message to be relative to the cipher
block; length of desired message must be less than cipher_block - offset """
def manipulate_cipher(cipher_block, plain_text_block, desired_block, offset):
    for i in range (offset, len(desired_block)):
        #print("cipherblock before: {0} plain_text before: {1} desired block before: {2}".format(cipher_block[i], plain_text_block[i], desired_block[i-offset]))
        cipher_block[i] = cipher_block[i] ^ plain_text_block[i] ^ desired_block[i - offset]
        #print("cipherblock after xor: {}".format(cipher_block[i]))
    return cipher_block

if __name__ == "__main__":
    main()