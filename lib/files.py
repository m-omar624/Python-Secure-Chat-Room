'''
* Group ID: A2G3
*  Group member names: Muhammad Omar, Venkatessh Kumar, Aradhya Singh
* Course:EECS 3482 A
* Description: receive a file, call for signing, and encrypt file before sending
                receive a sent file, call for decrypting
*
'''

from base64 import b64decode, b64encode
import os
import traceback
from os import walk
from decrypt import decrypt
from lib.comms import Message
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import bcrypt

from sign import save_signed_filed

#import tqdm
# Instead of storing files on disk,
# we'll save them in memory for simplicity
filestore = {}

def encrypt(data):
    # Encrypt the file so that
    # the user you send it to could  read
    data = data+".signed" # retrieve signed file
    f = open(os.path.join("files", data), "rb").read() #retrieve contents
    mac = f[:64] #retrieve mac
    f = f[64:] # retreive original file contents (we only want to encrypt file contents not mac)
    print("Please Press ENTER") # ready user for setting passworf
    key = input("Set password for file: ") #set password
    
    # fill password with '0' to meet AES limitation
    if len(key) < 16:
        fill = 16-len(key)
        for i in range(fill):
            key += "0"
    key = key[0:16] # if password entered is too large, only take first 16 characters
    salt = "1zz16byt3541t1zz" # fixed salt
    pwd = key+salt

    # bcrypt hasing of salted password
    pwd = b64encode(SHA256.new(bytes(pwd,"ascii")).digest())
    bcrypt_hash = bcrypt(pwd, 12)

    #write password into passwrod.txt
    p = open('password.txt','wb')
    p.write(bcrypt_hash)
    p.close()

    # begin AES CBC encryption
    cipher = AES.new(bytes(key,"ascii"),AES.MODE_CBC)
    cipherBytes = cipher.encrypt(pad(f, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(cipherBytes).decode('utf-8')
    encryptedFile = str(mac)+iv+ct # attach IV with ciphertext and attach unencrypted mac to the beginning of data
    
    # write into file
    out = open(os.path.join("files", data), "wb")
    out.write(bytes(encryptedFile, "ascii"))
    out.close()

    return bytes(encryptedFile, "ascii")


def verify_file(fn,f):
    # Verify the file was sent by the user
    # TODO: NO NEED TO WORRY FOR ASSIGNEMNT 1
    # Naive verification by ensuring the first line has the "passkey"
    pt = decrypt(fn)
    if pt != None:
        f = f.decode('utf-8')
        file = pt.decode("utf-8") #retrieve all except HMAC attached to message.
        mac = f[2:66] # since mac was in bytes format converting to string kept " b' " in the file, this is why we start from 2. retrieves mac
        key = "placeholderKey00000" # RETRIEVE DH KEY FROM FILE, THIS HAS NOT YET BEEN IMPLEMENTED
        key = bytes(key[0:16], "ascii") #AES limitation

        # begin HMAC authenticaiton
        authentication = HMAC.new(key, digestmod=SHA256)
        authentication.update(bytes(str(file), "ascii"))
        try:
            authentication.hexverify(mac)
            print("File Authenticated")
            return True
        except ValueError:
            print("Unauthorized File Transfer!")
            return False
    

def process_file(fn, f):
    if verify_file(fn,f):
        # encrypt and store the file
        filestore[fn] = f
        print("Stored the received file as %s" % fn)
    else:
        print("WARNING: The file cannot be verified...")


def recv_file(sconn):
    # Download the file from the other bot
    
    fn = str(sconn.recv(), "ascii")
    f = sconn.recv()
    print("Receiving %s" % fn)
    process_file(fn, f)
    fd = open("downloaded_file_%s" %fn, "wb")
    fd.write(f)
    fd.close()

###

def send_file(sconn):
     # for simplicity we'll keep the files
    #  in the "files" directoru
    files = {}
    for (dirpath, dirnames, filenames) in\
        walk("./files"):
        for i, f in enumerate(filenames):
            files[i]=f
    print("*** Available Files ***")
    for k, v in files.items():
        print(str(k)+") "+v)

    while True:
        f = input("Please choose which file [0 - "+
                    str(len(files)-1)+
                    "] to send:")
        try:
            fn = files[int(f)]
            break
        except:
            print("Incorrect file index, please try again""")
            traceback.print_exc()
            continue
    
    print("Signing File")
    save_signed_filed(fn) # call to sign file
    print("Encrypting File")
    f = encrypt(fn) # call to encrypt file

    print("Sending file")
    sconn.send(Message.FILE_TRANSFER)
    sconn.send(bytes(fn,"ascii"))
    sconn.send(f)

    # Grab the file and send it to another user
    #if fn not in filestore:
    #    print("That file doesn't exist in the botnet's filestore")
    #    return
    #print("Sending %s via P2P" % fn)
    #sconn.send(fn)
    #sconn.send(filestore[fn])
