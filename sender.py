# Shlomi Ben-Shushan, 311408264, Ofir Ben-Ezra, 206073488
import socket, sys
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# TODO: check if argv[1] is exsist with try - maybe in function?
Xname = sys.argv[1]  # 10.0.2.15 pc1
MESSAGES_FILE_NAME = "messages" + Xname + ".txt"
IPS_FILE_NAME = "ips.txt"
ips = []
ports = []


def loadIPsFile():
    try:
        ipFile = open(IPS_FILE_NAME, "r")
    except IOError:
        print("IPS File Not Found or path incorrect")
        exit(1)

        # start send message flow line by line
    for line in ipFile:
        print(line)
        try:
            ip, port = line.split(' ')
            port = port.rstrip()
            ips.append(ip)
            ports.append(port)
        except ValueError:
            print("IPS/PORT Problem")
    ipFile.close()


# Open and read messages file for get all the variables and start the flow
def handleMessagesFile():
    # save the public key from file

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

            password = bytes(password, 'utf-8')
            salt = bytes(salt, 'utf-8')
            message = bytes(message, 'utf-8')

            dest_ip = bytes(dest_ip, 'utf-8')
            dest_port = bytes(dest_port, 'utf-8'
                              )
            pathList = path.split(',')

        except ValueError:
            print("ARGS Problem - exit")
            messagesFile.close()
            exit(1)

        # Create symmetric key and Enc the msg with it
        k = genSymmetricKey(password, salt)
        c = encryptionByKey(k, message)

        # Create a msg from destIP||destPort||c
        msg = dest_ip+dest_port+c

        for mixServer in reversed(pathList):
            pk = handlePKFile(mixServer)
            l = encryptionByKey(pk, msg)
            mixIP = ips[int(mixServer)-1] # -1 because ips list start from index 0
            mixPort = ports[int(mixServer)-1] # -1 because portss list start from index 0
            msg = mixIP+mixPort+l

        sendMsg(l,mixIP,mixPort)

    messagesFile.close()
    return

# read public key from file
def handlePKFile(n):
    #try to load pk2 file
    try:
        pkFileName = 'pk'+n+'.pem'
        pkFile = open(pkFileName, 'rb')
        publicKeyText = pkFile.read()
        pk = serialization.load_pem_public_key(publicKeyText, None)
        pkFile.close()
    except IOError:
        print("PK"+n+" File Not Found or path incorrect")
        exit(1)
    return pk

# Generate symmetric key with the password and salt from the massages file
def genSymmetricKey(password, salt):
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
def encryptionByKey(key, message):
    token = key.encrypt(message)
    return token


# Send message to server
def sendMsg(l):
    print(l)
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
def main():
    loadIPsFile()
    handleMessagesFile()


main()
