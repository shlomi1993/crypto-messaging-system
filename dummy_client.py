import socket, sys, base64
from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key

password = b"password"
salt = b"password"

def Enc(key, data_string):
    cipher = Fernet(key)
    return cipher.encrypt(data_string.encode())
    
# Encryption the message with Symmetric key
def encryptionByKey(key, message):
    ciphertext = key.encrypt(message,
                             padding.OAEP(
                                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                 algorithm=hashes.SHA256(),
                                 label=None)
                             )
    return ciphertext

def genSymmetricKey(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return Fernet(key)

# Convert IP and Port from string to bytes
def convertIPandPORT(ip,port):
    strIpArr = ip.split('.')
    ipArr = [int(str) for str in strIpArr]
    ip = bytes(ipArr)
    port = int(port.rstrip())
    port = (port).to_bytes(2, 'big')
    return ip,port

def handlePKFile(n):
    # try to load pk2 file
    try:
        pkFileName = 'pk' + n + '.pem'
        pkFile = open(pkFileName, 'rb')
        pk = load_pem_public_key(pkFile.read(), backend = default_backend())
        pkFile.close()
    except IOError:
        print("PK" + n + " File Not Found or path incorrect")
        exit(1)
    return pk

TCP_IP = "127.0.0.1"
TCP_PORT = "5000"
BUFFER_SIZE = 1024

x,y = convertIPandPORT(TCP_IP, TCP_PORT)

message = "cccc"
k = genSymmetricKey(password, salt)
c = k.encrypt(message.encode())

msg = x + y + c

# print(msg)

pk = handlePKFile(str(2))
l = encryptionByKey(pk, msg)

print("sending l: " + str(l))    

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, int(TCP_PORT)))
s.send(l)
s.close()



