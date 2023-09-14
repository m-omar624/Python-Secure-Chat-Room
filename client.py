'''
* Group ID: A2G3
*  Group member names: Muhammad Omar, Venkatessh Kumar, Aradhya Singh
* Course:EECS 3482 A
* Description: Client program. Established connection with the server
*
'''
from base64 import b64decode, b64encode
from ctypes import sizeof
from Crypto.Hash import HMAC, SHA256
import socket
import time
import threading
import sys, os, getopt
from CA import generateCertificate
from chat import Chat
import traceback
from os import walk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from lib.comms import Message
import getpass
import pyfiglet

from lib.comms import StealthConn
from lib.files import send_file

class Client:

       def __init__(self,username=None, sconn=None, port=None):
           self._port = port
           self._username = username
           self._sconn= sconn
           conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           

           self._chat_sessions ={}
           try:
                print("Found server on port %d" % port)
                conn.connect(("localhost", port))
                self._sconn = StealthConn(conn, client=True)

           except socket.error as se:
                print("No server found on port %d" % port,se)

       def get_session(self):
            return self._sconn

       def accept_connection(self):
            
            try:
                while True:
                    cmd = self._sconn.recv()
                    #print("Client command", cmd)
                    if cmd == Message.LIST:  #b'LIST':
                        data =  self._sconn.recv()
         
                        print("\n ===== Online User ====:")
                        for u in data.split():
                            print("| * ", u.decode("utf8"), " "*(16-len(u)), "|")
                        print("="*20)

                    elif cmd == Message.CHAT or\
                         cmd == Message.FILE: # received a chat or file transfer  request

                        with_user = self._sconn.recv()
                        print("\nInitiating a chat session with ", with_user.decode("utf"))
                        for u in data.split():
                            print("| * ", u.decode("utf8"), " "*(16-len(u)), "|")
                            
                        print("="*20)

                        chat = Chat(with_user.decode("utf-8"))
                        print("Sending the chat session details")
                        if cmd == Message.CHAT:
                            self._sconn.send(Message.CHAT_SESSION)
                        else:
                             self._sconn.send(Message.FILE_TRANSFER)

                        self._sconn.send(with_user)
                        self._sconn.send(bytes(self._username+"|"+str(chat._port), "ascii"))

                        chat.start_session()

                    elif cmd == Message.CHAT_SESSION or\
                         cmd == Message.FILE_TRANSFER:

                        # receive chat session info
                        data = self._sconn.recv()
                        chat_port = data.decode("utf-8").split("|")[1]
                        at_user =   data.decode("utf-8").split("|")[0]
                        print("Received port", int(chat_port))
                        #address = self._sconn.recv()

                        try:
                            chat_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            print("Chat server on port %d" % int(chat_port))
                            chat_conn.connect(("localhost", int(chat_port)))
                            chat_sconn = StealthConn(chat_conn, client=True)

                            SignedCertificate = generateCertificate(self._username, chat_sconn._secret) # request certification
                            print("certificate created")
                            # keep the session conn for subsequent msgs
                            self._chat_sessions.update({at_user:chat_sconn})

                            if cmd == Message.CHAT_SESSION:
                                # Send Ecnrypted Message attached with MAC

                                key = chat_sconn._secret # retrieve DH key
                                key = key[0:16]
                                key = bytes(key, "ascii")

                                msg = input("Enter your message to ["+at_user+"]:")
                                msg = bytes(msg,"ascii") # convert to bytes for encryption
                                
                                # Encrypt using AES CBC Block Cipher
                                cipher = AES.new(key,AES.MODE_CBC)
                                ciphertextb = cipher.encrypt(pad(msg,AES.block_size))
                                iv = b64encode(cipher.iv).decode('utf-8')
                                ct = b64encode(ciphertextb).decode('utf-8')
                                msg = ct+iv # attach IV to CipherText

                                # Generate MAC
                                msg = bytes(msg,"ascii") # convert to bytes once again for MAC
                                h = HMAC.new(key, digestmod=SHA256)
                                h.update(msg)
                                mac = h.hexdigest()
                                msg = bytes(str(mac), "ascii")+msg+b'*' # attach MAC (in bytes) to the beginning of the message
                                chat_sconn.send(msg+SignedCertificate) # send message along with signed certificate
                            
                            elif cmd == Message.FILE_TRANSFER:
                                send_file(chat_sconn)

                        except:
                            print("Couldn't establish chat connection")
                            traceback.print_exc()

                    elif cmd == Message.ECHO:
                        # Ensure that what we sent is what we got back
                        echo = self._sconn.recv()
                        print("Echo>", echo)
                        # If the msg is X, then terminate the connection
                        if echo.lower() == 'x' or echo.lower() == "exit" or echo.lower() == "quit":
                            self._sconn.close()

                    elif cmd == Message.ERROR:
                        print("Server error, try again")


            except socket.error:
                print("Connection closed unexpectedly", socket.error)

       def connect(self):
                # Set verbose to true so we can view the encoded packets
        try:
            if self._sconn:
                self._sconn.verbose = True
                authenticated = False
                while not authenticated:
                    self._username = input("Username>")
                    self._sconn.send(Message.AUTH)
                    self._sconn.send(bytes(self._username, "ascii"))
                    password = getpass.getpass("Password:")
                    #password = input("Passoword:")
                    self._sconn.send(bytes(password, "ascii"))
                    cmd = self._sconn.recv()
                    if cmd == Message.ACK:
                        os.system("clear")
                        result = pyfiglet.figlet_format("Welcome to the Matrix", font = "digital" )
                        print(result)
                        authenticated =  True

                        thr=threading.Thread(target=self.accept_connection)
                                             #kwargs={ 'sconn': self._sconn})
                        thr.setDaemon(True)
                        thr.start()
                        while True:
                            time.sleep(0.1)
                            # Naive command loop
                            # There are better ways to do this,
                            # but the code should be clear
                            raw_cmd = input("["+self._username+"] Enter command: ")
                            cmd = raw_cmd.split()

                            if not cmd:
                                print("You need to enter a command...")
                                continue
                            # Commands
                            # Echo is primarily meant for testing
                            # (the receiver will echo what it hears back)
                            if len(cmd) > 1:
                                if cmd[0].lower() == "echo":
                                    if cmd[1].lower() == "server":
                                        msg = input("Echo> ")
                                        self._sconn.send(Message.ECHO)
                                        byte_msg = bytes(msg, "ascii")
                                        self._sconn.send(byte_msg)

                                 # Initiate file sending to client
                                elif cmd[0].lower() == "send":
                                    at_user = cmd[1]
                                    if cmd[1].startswith("@"):
                                        at_user = at_user[1:len(at_user)]
                                        self._sconn.send(Message.FILE)
                                        if at_user != self._username:
                                            self._sconn.send(bytes(at_user, "ascii"))
                                        else:
                                            print("Cannot send file to yourself!")

                                else:
                                    print("Command ["+ raw_cmd + "] not recognised")

                            elif cmd[0].lower().startswith("@"):
                                # @<username>
                                # TODO before sending text check if user is logged in

                                at_user = cmd[0]
                                if at_user[0] == '@':
                                    at_user = at_user[1:len(at_user)]
                                    try:
                                        #check if session is ON
                                        chat_sconn = self._chat_sessions[at_user]
                                        msg = input("Enter your message to ["+at_user+"]:")
                                        chat_sconn.send(bytes(msg, "ascii"))
                                    except:
                                        # initate a new chat
                                        # session
                                        print("User Not Online")
                                        self._sconn.send(Message.CHAT)
                                        if at_user != self._username:
                                            self._sconn.send(bytes(at_user, "ascii"))
                                        else:
                                            print("You cannot chat with yourself!")
                                        #send msg to the user

                                else:
                                    print("@<user>")


                            elif cmd[0].lower() == "list":
                                self._sconn.send(Message.LIST)

                                # Exit command
                            elif cmd[0].lower() == "quit" or cmd[0].lower() == "exit":
                                break
                            else:
                                print("Command ["+ raw_cmd + "] not recognised")
        except Exception as e:
            print("Couldn't establish a connection", e)
            traceback.print_exc()



def main(argv):

    #default port
    server_port=1337
    try:
        opts, args = getopt.getopt(argv,"hp:",["port="])
    except getopt.GetoptError:
        print('client.py -port <port>')
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print('client.py -port <port>')
            sys.exit()
        elif opt in ("-p", "--port"):
            if arg:
                server_port = int(arg)

    Client(port=server_port).connect()

if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        print("\nDone!")
