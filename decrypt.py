'''
* Group ID: A2G3
*  Group member names: Muhammad Omar, Venkatessh Kumar, Aradhya Singh
* Course:EECS 3482 A
* Description: decrypt an AES CBC encrypted file
*
'''

from base64 import b64decode, b64encode
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import bcrypt_check

def decrypt_content(f):
    # HINT: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme plaintext
    # As such, we just convert it back to ASCII and print it out
    print("Please Press ENTER") # read receiver for password input
    key = input("Enter File Password: ") # receiver inputs password
    try:
        f = f.decode('utf-8')
        iv = b64decode(f[67:91]) # retrieve IV
        ct = b64decode(f[91:]) # retrieve ciphertext
        
        #fill password with '0' to meet AES limitation
        if len(key) < 16:
            fill = 16-len(key)
            for i in range(fill):
                key += "0"

        key = key[0:16] # if password entered is too large, only take first 16 characters
        key = bytes(key,"ascii")
        salt = b'1zz16byt3541t1zz' # fixed salt
        pwd = key+salt
        pwdHash = open('password.txt','r').read() #retrieve hashed password
        
        #bcrypt checking if password matches
        try:
            pwd = b64encode(SHA256.new(pwd).digest())
            bcrypt_check(pwd, pwdHash)
            print("Password Success")
        except ValueError:
            print("Incorrect password")
        
        # decrypt file using password as key
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print("File Decrypted")
        return pt
    except(ValueError, KeyError):
        print("incorrect password")
        return None


def decrypt(fn):
    f = open(os.path.join("files", fn+".signed"), "rb").read()
    result = decrypt_content(f)
    return result
