# Shlomi Ben-Shushan, 311408264, Ofir Ben-Ezra, 206073488

import socket, sys, random
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

BUFFER_SIZE = 20480

# Parse the given number
try:
	number = int(sys.argv[1])
	with open("ips.txt", "r") as ips:
	    ip, port = ips.read().split("\n")[number - 1].split(" ")
	port = int(port)
except:
    print("Invalid given number or ips.txt file.")
    exit(-1)

# Open server's socket.
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', port))
s.settimeout(0.1)
s.listen(5)

# Get private key.
with open("sk" + str(number) + ".pem", "rb") as skey:
	sk = load_pem_private_key(skey.read(), password = None, backend = default_backend())

# Set array of deliveries -- each delivery is a touple of [IP, Port, Message].
deliveries = []

# Server's main loop.
doing = False
while True:

    # Recieve data.
    try:
        conn, addr = s.accept()
        conn.settimeout(1)
        data = conn.recv(BUFFER_SIZE)
    except socket.timeout:
        data = ""

    # Once data recieved, decrypt and parse it.
    if len(data) > 0:

        # DEBUG
        print("message recieved")
        print("delveries: " + str(len(deliveries)))

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

    # DEBUG
    # if time_splitted[2] != "00" and time_splitted[2] != "10" and time_splitted[2] != "20" and time_splitted[2] != "30" and time_splitted[2] != "40" and time_splitted[2] != "50":
    #    doing = False

    elif doing == False:
        doing = True
        if len(deliveries) > 0:
            delivery = random.choice(deliveries)
            deliveries.remove(delivery)
            t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:

                # DEBUG
                print("send message to " + delivery[0] + ":" + str(delivery[1]))

                t.connect((delivery[0], delivery[1]))
                t.send(delivery[2])
            finally:
                t.close()
