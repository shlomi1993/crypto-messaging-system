import socket, sys
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# TODO: check if argv[1] is exsist with try - maybe in function?
Xname = sys.argv[1]  # 10.0.2.15 pc1
MESSAGES_FILE_NAME = "messages" + Xname + ".txt"
PK2_FILE = "pk2.pem"


# Open and read messages file for get all the variables and start the flow
def handleMessagesFile(self):
    # save the public key from file
    pk2 = handlePK2File()

    try:
        messagesFile = open(MESSAGES_FILE_NAME, "r")
    except IOError:
        print("Messages File Not Found or path incorrect")
        exit(1)

    # start send message flow line by line
    for line in messagesFile:
        print(line)
        try:
            message, path, round, password, salt, dest_ip, dest_port = line.split(' ')
        except ValueError:
            print("ARGS Problem - exit")
            messagesFile.close()
            exit(1)
        k = genSymmetricKey(password,salt)
        c = encryptionByKey(k, message)
        msg = dest_ip+dest_port+c
        l = encryptionByKey(pk2, msg)
        sendMsg(l)

    messagesFile.close()
    return

# read public key from file
def handlePK2File(self):
    #try to load pk2 file
    try:
        pk2File = open(PK2_FILE, "r")
    except IOError:
        print("PK2 File Not Found or path incorrect")
        exit(1)
    pk2 = RSA.importKey(open("public.pem", "rb"))
    pk2File.close()
    return pk2

# Generate symmetric key with the password and salt from the massages file
def genSymmetricKey(self, password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    fKey = Fernet(key)
    return fKey


# Encryption the message with Symmetric key
def encryptionByKey(self, key, message):
    token = key.encrypt(message)
    return token


# Send message to server
def sendMsg(self, l):
    return
    # while (True):
    #     s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #     sendMsg = input()
    #
    #     addr = (serverIP, int(serverPort))
    #     s.sendto(sendMsg.encode('utf-8'), addr)
    #
    #     data, addr = s.recvfrom(1024)
    #     reciveMsg = data.decode("utf-8")
    #     if (reciveMsg != 'ERROR!'):
    #         currentline = reciveMsg.split(",")
    #         print(currentline[1])
    #     else:
    #         print(reciveMsg)
    #
    #     s.close()


# Program Flow
def main(self):
    handleMessagesFile()


main()
