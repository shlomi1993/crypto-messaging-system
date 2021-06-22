# Shlomi Ben-Shushan, 311408264, Ofir Ben-Ezra, 206073488

import socket, sys, random
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Parse the given number
try:
	number = int(sys.argv[1])
except:
    exit(-1)
port = 5000 # need to change to 8999 + number

# Open server's socket.
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', port))
s.listen(5)
conn, addr = s.accept()
conn.settimeout(1)

# Get private key.
with open("sk" + str(number) + ".pem", "rb") as skey:
	sk = load_pem_private_key(skey.read(), password = None, backend = default_backend())
 
# Set array of deliveries -- each delivery is a touple of [IP, Port, Message].
deliveries = []

# Server's main loop.
doing = False
while True:
    
    # Recieve data.
    data = conn.recv(4096)
    
    # Once data recieved, decrypt and parse it.
    if len(data) > 0:
        
        # Decryption. 
        plaintext = sk.decrypt(data,
				padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()),
					algorithm = hashes.SHA256(),
					label = None)
				)
        
        # Parse IP.
        ip = plaintext[:4]
        ip = str(ip[0]) + "." + str(ip[1]) + "." + str(ip[2]) + "." + str(ip[3])
        
        # Parse port.
        port = plaintext[4:6]
        port = int(hex(port[0])[2:] + hex(port[1])[2:], 16)
        
        # Parse message.
        msg = plaintext[6:]   
         
        # Add new delivery to deliveries.
        deliveries.append([ip, port, msg])
    
    # Check time.
    time_splitted = datetime.now().strftime("%H:%M:%S").split(":")
    
    # Each rounded minute, pick a random delivery and send it over TCP to the next server\client.
    if time_splitted[2] != "00":
        doing = False
    elif doing == False:
        doing == True
        delivery = random.choice(deliveries)
        if len(delivery) > 0:
            t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            t.connect((delivery[0], delivery[1]))
            t.send(delivery[2])
            t.close()