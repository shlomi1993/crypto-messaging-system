# Shlomi Ben-Shushan, 311408264, Ofir Ben-Ezra, 206073488
import socket, sys
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
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
            ip, port = convertIPandPORT(ip, port)
            ips.append(ip)
            ports.append(port)
        except ValueError:
            print("IPS/PORT Problem")
    ipFile.close()

# Convert IP and Port from string to bytes
def convertIPandPORT(ip,port):
    strIpArr = ip.split('.')
    ipArr = [int(str) for str in strIpArr]
    ip = bytes(ipArr)
    port = int(port.rstrip())
    port = (port).to_bytes(2, 'big')
    return ip,port


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

            # Convert variables
            round = int(round)
            password = bytes(password, 'utf-8')
            salt = bytes(salt, 'utf-8')
            message = bytes(message, 'utf-8')

            dest_ip, dest_port = convertIPandPORT(dest_ip, dest_port)
            pathList = path.split(',')

        except ValueError:
            print("ARGS Problem - exit")
            messagesFile.close()
            exit(1)

        # Create symmetric key and Enc the msg with it
        k = genSymmetricKey(password, salt)
        c = k.encrypt(message)
        # Create a msg from destIP||destPort||c
        msg = dest_ip + dest_port + c

        for mixServer in reversed(pathList):
            pk = handlePKFile(mixServer)
            l = encryptionByKey(pk, msg)
            mixIP = ips[int(mixServer) - 1]  # -1 because ips list start from index 0
            mixPort = ports[int(mixServer) - 1]  # -1 because portss list start from index 0
            msg = mixIP + mixPort + l

        sendMsg(l, mixIP, mixPort)

    messagesFile.close()
    return


# read public key from file
def handlePKFile(n):
    # try to load pk2 file
    try:
        pkFileName = 'pk' + n + '.pem'
        pkFile = open(pkFileName, 'rb')
        publicKeyText = pkFile.read()
        pk = serialization.load_pem_public_key(publicKeyText, None)
        pkFile.close()
    except IOError:
        print("PK" + n + " File Not Found or path incorrect")
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
    ciphertext = key.encrypt(message,
                             padding.OAEP(
                                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                 algorithm=hashes.SHA256(),
                                 label=None)
                             )
    return ciphertext


# Send message to server
def sendMsg(l, ip, port):
    print(l)
    print(ip)
    print(port)
    print("".join("\\x{:02}".format(b) for b in port))

    # Debug
    checkRecive(l)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sendMsg = l

    addr = (ip, int(port))
    s.sendto(sendMsg.encode('utf-8'), addr)

    data, addr = s.recvfrom(1024)
    reciveMsg = data.decode("utf-8")
    if (reciveMsg != 'ERROR!'):
        currentline = reciveMsg.split(",")
        print(currentline[1])
    else:
        print(reciveMsg)

    s.close()
    return

# Debug
def checkRecive(l):

    return


# Program Flow
def main():
    loadIPsFile()
    handleMessagesFile()


main()
