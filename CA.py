'''
* Group ID: A2G3
*  Group member names: Muhammad Omar, Venkatessh Kumar, Aradhya Singh
* Course:EECS 3482 A
* Description: Certification Authority
*
'''
from base64 import b64encode
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Signature import pkcs1_15


#Generate a public/private key pair for the certificate authority. The public key of the CA is self-signed.

def generateCAkeys():
    key = RSA.generate(2048) # generate 2048bit RSA key

    # write private key into file
    f = open('myPrivateKey.pem','wb')
    f.write(key.export_key('PEM'))
    f.close()

    #write public key into file
    f = open('myPublicKey.pem','wb')
    key = key.public_key()
    f.write(key.export_key('PEM'))
    f.close()
    return 

#FUNCTION: function to get public key from file
def getCAPublicKey():
    f = open('myPublicKey.pem','r')
    key = RSA.import_key(f.read())
    return key

def generateCertificate(user_id, user_pub_key):

    # retrieve private key from file
    f = open('myPrivateKey.pem','r')
    privkey = RSA.import_key(f.read())

    hashed = SHA256.new(bytes(str(user_id+user_pub_key), "ascii")) # get hashcode of unsigned certificate

    # begin AES CBC Encryption
    cipherKey = privkey.export_key()[32:48] # get cipher key (AES limitaion)
    cipher = AES.new(cipherKey,AES.MODE_CBC)
    ciphertextb = cipher.encrypt(pad(bytes(str(hashed), "ascii"),AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ciphertextb).decode('utf-8')
    unsignedCert = ct+iv # attach IV to CipherText

    # Begin PKCS1 1.5 signature
    Cert = SHA256.new(bytes(unsignedCert, "ascii"))
    signedCert = pkcs1_15.new(privkey).sign(Cert)
    return bytes(Cert.hexdigest(), "ascii")+signedCert # attach signature to the end of the certificate
