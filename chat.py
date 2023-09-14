'''
* Group ID: A2G3
*  Group member names: Muhammad Omar, Venkatessh Kumar, Aradhya Singh
* Course:EECS 3482 A
* Description: chat and file transfer handler
*
'''
from multiprocessing.sharedctypes import Value
import socket
import time
import threading
import sys, getopt

from lib.comms import Message
from lib.comms import StealthConn
from lib.files import recv_file
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import HMAC, SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA

class Chat():
    def __init__(self, with_user=None):
        self._with_user = with_user
        self._conn = None
        self._sconn = None
        self._address = None
        self._port = None
        self._s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._s.bind(("localhost", 0))
        self._s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._s.listen(5)

        self._port = self._s.getsockname()[1]

    def get_connection_port(self):
        return self._port

    def get_session(self):
        return self._sconn

    def chat_thread(self):
        try:

            print("Chat session is on port %d" % self._port)
            print("Waiting for a connection...")
            self._conn, self._address = self._s.accept()
            print("Accepted a connection from %s..." % (self._address,))

            # Start a new thread per connection
            # We don't need to specify it's a daemon thread as daemon status is inherited
            threading.Thread(target=self.accept_connection).start()
                                #kwargs={ 'conn': self._conn}).start()
            time.sleep(2)
        except socket.error as e:
            print("Port %d not available" % self._port, e)
            exit()

    def accept_connection(self):
        try:
            self._sconn = StealthConn(self._conn, server=True)
            # The sender is either going to chat to us or send a file
            while True:
                try:
                    recv = self._sconn.recv()
                    if recv == Message.FILE_TRANSFER:
                        print("Ready to receive files")
                        recv_file(self._sconn)
                    else:
                        # decrypt and authenticate message     
                        msg = recv[0:str(recv).index('*')-2]
                        certificateAndSignature = recv[str(recv).index('*')-1:]                   
                        msg = msg.decode("utf-8")
                        dkey = self._sconn._secret #retrieve DH key
                        dkey = dkey[0:16]
                        dkey = bytes(dkey, "ascii")
                        mac = msg[0:64] #retrieve HMAC
                        
                        # Message Decryption
                        iv = b64decode(msg[-24:]) # retrieve IV attached to message
                        ct = b64decode(msg[64:(len(msg)-24)]) # retreieve the encrypted message itself

                        cipher = AES.new(dkey, AES.MODE_CBC, iv)
                        pt = unpad(cipher.decrypt(ct), AES.block_size)

                        print(self._with_user+"> "+pt.decode("utf-8"))
                        
                        # HMAC Authentication
                        msg = msg[64:] #retrieve all except HMAC attached to message.
                        authentication = HMAC.new(dkey, digestmod=SHA256)
                        authentication.update(bytes(str(msg), "ascii"))
                        try:
                            authentication.hexverify(mac)
                            print(self._with_user+"> Message Authenticated")
                        except ValueError:
                            print(self._with_user+"> Unauthorized Message!")
                        
                        # check if certificate received
                        if certificateAndSignature is None:
                            print("certificate not recieved")
                        else:
                            certificate = certificateAndSignature[:64] # retrieve certificate
                            signature = certificateAndSignature[64:] # retrieve signature
                            
                            # read public key from file
                            f = open('myPublicKey.pem','r')
                            key = RSA.import_key(f.read())
                            f.close()

                            #Begin PKCS1 1.5 verification
                            certHashCode = SHA256.new(certificate)
                            try:
                                pkcs1_15.new(key).verify(certHashCode, signature)
                                print("The signature is valid.")
                            except (ValueError, TypeError):
                                print("The signature is not valid.")

                except: #not a chat message
                     None
                time.sleep(2)
        except socket.error:
            print("Connection closed unexpectedly", socket.error)

    def start_session(self):
        # Start a new thread to accept a chat session connection
        thr = threading.Thread(target=self.chat_thread())
        # Daemon threads exit when the main program exits
        # This means the server will shut down automatically when we quit
        thr.setDaemon(True)
        thr.start()
