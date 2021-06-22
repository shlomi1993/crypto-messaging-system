import socket, sys
from datetime import datetime
import hashlib, base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key

try:
	number = int(sys.argv[1])
except:
    exit(-1)
port = 4000 + number

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', port))
s.listen(5)
conn, addr = s.accept()
conn.settimeout(2)

with open("sk" + str(number) + ".pem", "rb") as skey:
	sk = load_pem_private_key(skey.read(), password = None, backend = default_backend())

def send_messages():
    print("Send stuff")

messages = []

doing = False
while True:
    
    data = conn.recv(4096)
    
    if len(data) > 0:
        # print(data)
        # size = len(data)
        # bip = bytearray(size)
        # bport = bytearray(size)
        # bmsg = bytearray(size)
        
        # print(type(data))
        
        # ip = data[:4]
        # i = 0
        # while i < len(ip):
        #     bip[i] = ip[i]
        #     i += 1
        
        # bip = bytes(bip)
        # bport = bytes(bport)
        # bmsg = bytes(bmsg)
            
        # i = 0
        # while i < len(bip):
        #     print(bip[i])
        # print("\n\n\n\n")
        # print(bip)
        # port = data[4:6]
        # msg = data[6:]
        
        # print(ip)
        # print(port)
        # print(msg)
        
        plaintext = sk.decrypt(data,
				padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()),
					algorithm = hashes.SHA256(),
					label = None)
				)
        

        print(plaintext)
        messages.append(plaintext)
    
    
    time = datetime.now().strftime("%G:%M:%S")
    time_splitted = time.split(":")
    
    if time_splitted != 00:
        doing = False
        
    elif doing == False:
        send_messages()