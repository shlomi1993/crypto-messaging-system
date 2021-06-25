# Shlomi Ben-Shushan, 311408264, Ofir Ben-Ezra, 206073488

import socket, sys, random, threading, time
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

BUFFER_SIZE = 20480

# Set activation time.
time_interval = str(random.randint(0, 59)).zfill(2)

# Parse the given number
number = int(sys.argv[1])
with open("ips.txt", "r") as ips:
    ip, port = ips.read().split("\n")[number - 1].split(" ")
    print("server: ", ip, ":", port) # DEBUG
    
# Get private key.
with open("sk" + str(number) + ".pem", "rb") as skey:
	sk = load_pem_private_key(skey.read(), password = None, backend = default_backend())
    
# Open server's socket.
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', int(port)))
s.settimeout(0.1)
s.listen(5)

# Set array of deliveries -- each delivery is a touple of [IP, Port, Message].
deliveries = []

def addDelivery(data):
    print("message recieved") # DEBUG
    
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


# This function opens a socket, send the message of the given delivery to its IP and port, and close the socket.
def send(delivery):
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        print("send message to " + delivery[0] + ":" + str(delivery[1])) # DEBUG
        t.connect((delivery[0], delivery[1]))
        t.send(delivery[2])
    finally:
        t.close()


# This function sends all messages in deliveries array each time interval.
def sendingThread():
    doing = False
    while True:    
        time_splitted = datetime.now().strftime("%H:%M:%S").split(":")

        # if time_splitted[2] != time_interval:
        if time_splitted[2] != "00" and time_splitted[2] != "10" and time_splitted[2] != "20" and time_splitted[2] != "30" and time_splitted[2] != "40" and time_splitted[2] != "50": # DEBUG
            doing = False
        elif doing == False:
            doing = True
            while len(deliveries) > 0:
                delivery = random.choice(deliveries)
                deliveries.remove(delivery)
                threading.Thread(target=send, args=(delivery,)).start()


# Activate sendingThread in a different thread.
threading.Thread(target=sendingThread, args=()).start()

# Server's main loop.
while True:

    # Recieve data.
    try:
        conn, addr = s.accept()
        conn.settimeout(1)
        data = conn.recv(BUFFER_SIZE)
    except socket.timeout:
        data = ""

    # Once data recieved, decrypt it, parse it and add new delivery - in a different thread.
    if len(data) > 0:
        threading.Thread(target=addDelivery, args=(data,)).start()