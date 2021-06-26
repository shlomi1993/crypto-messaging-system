# Shlomi Ben-Shushan, 311408264, Ofir Ben-Ezra, 206073488

import socket, sys
import base64
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MESSAGES_FILE_NAME = "messages" + sys.argv[1] + ".txt"
ips = []
ports = []

# Load IPs and ports from ips.txt file.
def loadIPsFile():
    try:
        ipFile = open("ips.txt", "r")
    except IOError:
        print("IPS File Not Found or path incorrect")
        exit(1)

    # Start send message flow line by line
    for line in ipFile:
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
# save all massages details in a tuples of (round,details) in msgList
# and then sort it by round and return it
def handleMessagesFile():
    
    msgList = []
    try:
        messagesFile = open(MESSAGES_FILE_NAME, "r")
    except IOError:
        exit(1)

    # start send message flow line by line
    for line in messagesFile:
        
        # save msg details in list
        try:
            
            message, path, round, password, salt, dest_ip, dest_port = line.rsplit(' ', 6)

            # Convert variables
            password = bytes(password, 'utf-8')
            salt = bytes(salt, 'utf-8')
            message = bytes(message, 'utf-8')
            dest_ip, dest_port = convertIPandPORT(dest_ip, dest_port)
            pathList = path.split(',')
            round = int(round)
            msgDetails =[message,pathList,password,salt,dest_ip,dest_port]
            msgList.append((round, msgDetails))

        except ValueError:
            messagesFile.close()
            exit(1)
            
    messagesFile.close()
    msgList = sorted(msgList, key=lambda msg: msg[0])  # sort by round of the msg
    return msgList

def handelOneMessage(msgDetails):
    
    # extract details
    message, pathList, password, salt, dest_ip, dest_port = msgDetails

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

# Load public key from file
def handlePKFile(n):
    try:
        pkFileName = 'pk' + n + '.pem'
        pkFile = open(pkFileName, 'rb')
        publicKeyText = pkFile.read()
        pk = load_pem_public_key(publicKeyText, backend = default_backend())
        pkFile.close()
    except IOError:
        exit(1)
    return pk

# Generate symmetric key with the password and salt from the massages file
def genSymmetricKey(password, new_salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=new_salt, iterations=100000, backend=default_backend())
    return Fernet(base64.urlsafe_b64encode(kdf.derive(password)))

# Encryption the message with Symmetric key
def encryptionByKey(key, message):
    return key.encrypt(message,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None)
                        )

# Send message to server
def sendMsg(msg, ip, port):

    # Parse IP and port.
    ip = str(ip[0]) + "." + str(ip[1]) + "." + str(ip[2]) + "." + str(ip[3])
    port = int(hex(port[0])[2:] + hex(port[1])[2:], 16)

    # Open a socket, send messsage and close the socket.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))
    s.send(msg)
    s.close()


# Program Flow
start_seconds = datetime.now().strftime("%H:%M:%S").split(":")[2]
currentRound = 0
doing = False
loadIPsFile()
msgListSortedByRounds = handleMessagesFile()
maxRound = msgListSortedByRounds[-1][0]
while currentRound <= maxRound:
    current = datetime.now().strftime("%H:%M:%S").split(":")[2]
    if current != start_seconds:
        doing = False
    elif doing == False:
        doing = True
        for msg in msgListSortedByRounds:
            if (msg[0] == currentRound):
                handelOneMessage(msg[1])
        currentRound += 1