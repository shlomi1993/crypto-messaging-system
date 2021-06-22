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

def Enc(key, data_string):
    cipher = Fernet(key)
    return str(cipher.encrypt(data_string.encode()))
    
# Encryption the message with Symmetric key
def encryptionByKey(key, message):
    ciphertext = key.encrypt(message,
                             padding.OAEP(
                                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                 algorithm=hashes.SHA256(),
                                 label=None)
                             )
    return ciphertext

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
TCP_PORT = 4002
BUFFER_SIZE = 1024

data = "cccc"
k = Fernet.generate_key()
c = Enc(k, data)
msg = TCP_IP + str(TCP_PORT) + c

print(msg)
print("\n")

pk = handlePKFile(str(2))
l = encryptionByKey(pk, msg.encode())


print("sending l: " + str(l))    

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
s.send(l)
s.close()

