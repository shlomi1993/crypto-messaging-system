# Shlomi Ben-Shushan, 311408264, Ofir Ben-Ezra, 206073488

import socket, sys, random
from datetime import datetime
from threading import Thread, Lock
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Set activation time.
interval = datetime.now().strftime("%H:%M:%S").split(":")[2]

# Parse the given number.
number = int(sys.argv[1])

# Get IP address and port number.
with open("ips.txt", "r") as ips:
    ip, port = ips.read().split("\n")[number - 1].split(" ")
    
# Load private key.
with open("sk" + str(number) + ".pem", "rb") as skey:
	sk = load_pem_private_key(skey.read(), password = None, backend = default_backend())
    
# Open server's socket.
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', int(port)))
s.settimeout(0.1)
s.listen(5)    

# Set array of deliveries -- each delivery is a touple of [IP, Port, Message].
deliveries = []
mutex = Lock()

# This function add a new delivery while holding other threads from using the deliveries array.
def addDelivery(touple):
    mutex.acquire()
    deliveries.append(touple)
    mutex.release()

# This function pops a random delivery while holding other threads from using the deliveries array.
def popDelivery():
    delivery = None
    mutex.acquire()
    delivery = random.choice(deliveries)
    deliveries.remove(delivery)
    mutex.release()
    return delivery

# This function opens a socket, send a message and close the socket.
def send(delivery):
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        t.connect((delivery[0], delivery[1]))
        t.send(delivery[2])
    finally:
        t.close()

# This function send all the deliveries each time interval. Each delivery is sent in a different thread.
def sendingThread():
    doing = False
    while True:    
        current = datetime.now().strftime("%H:%M:%S").split(":")[2]
        if current != interval:
            doing = False
        elif doing == False:
            doing = True
            while len(deliveries) > 0:
                Thread(target=send, args=(popDelivery(),)).start()
                
# This is a client handler function that is called for each client in a different thread.
def handleClient(conn):
    data = conn.recv(20480)
    if len(data) > 0:            
        plaintext = sk.decrypt(data,
                padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()),
                    algorithm = hashes.SHA256(),
                    label = None)
                )
        ip = plaintext[:4]
        ip = str(ip[0]) + "." + str(ip[1]) + "." + str(ip[2]) + "." + str(ip[3])
        port = plaintext[4:6]
        port = int(hex(port[0])[2:] + hex(port[1])[2:], 16)
        msg = plaintext[6:]
        addDelivery([ip, port, msg])
        
# This functions accepts new clients in a loop.
def clientsThread():
    while True:
        try:
            conn, addr = s.accept()
            Thread(target=handleClient, args=(conn,)).start()
        except socket.timeout:
            continue
    
# Activate server's threads.
Thread(target=sendingThread, args=()).start()
Thread(target=clientsThread, args=()).start()