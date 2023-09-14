
'''
* Group ID: A2G3
*  Group member names: Muhammad Omar, Venkatessh Kumar, Aradhya Singh
* Course:EECS 3482 A
* Description: sign files with HMAC
*
'''
from Crypto.Hash import HMAC, SHA256
import os


def sign_file(f):
    # TODO: For Part 2, you'll use public key crypto here
    # The existing scheme just ensures the updates start with the line 'EECS3482'
    # This is naive -- replace it with something better!
    key = "placeholderKey00000"# DH KEY MUST BE RETRIEVED FROM FILE,   THIS  IS NOT YET IMPLEMENTED
    key = key[0:16] # Key size limitation
    key = bytes(key, "ascii") #convert to bytes
    
    #create HMAC
    h = HMAC.new(key, digestmod=SHA256)
    h.update(f)
    mac = h.hexdigest()

    f = bytes(mac, "ascii")+ f #attach MAC to file
    return f


def save_signed_filed(fn):
    f = open(os.path.join("files", fn), "rb").read()
    signed_f = sign_file(f)
    signed_fn = os.path.join("files", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    #print("Signed file written to", signed_fn)
