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
    
    cipher_text = io.BytesIO(cipher_string)
    plain_text_stream = io.BytesIO()
    cbc_decrypt(cipher_text, plain_text_stream, cipher, iv)
    plain_text = plain_text_stream.getvalue()
    plain_text = plain_text.decode('utf-8')
    return pattern in plain_text

if __name__ == "__main__":
    main()