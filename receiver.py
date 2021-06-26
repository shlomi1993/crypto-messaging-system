# Shlomi Ben-Shushan, 311408264, Ofir Ben-Ezra, 206073488

import socket, sys, base64, threading
from cryptography.fernet import Fernet
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

BUFFER_SIZE = 20480

# Get arguments
password = sys.argv[1].encode()
salt = sys.argv[2].encode()
port = int(sys.argv[3])

# Generate a symmetric key.
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
k = Fernet(base64.urlsafe_b64encode(kdf.derive(password)))

# Create a socket, bind and listen.
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', port))
s.settimeout(0.1)
s.listen(5)

# This is a client handler function that called for each client in a different thread.
def handleClient(conn):
    data = conn.recv(BUFFER_SIZE)
    if len(data) > 0:
        plaintext = k.decrypt(data).decode()
        time = datetime.now().strftime("%H:%M:%S")
        print(plaintext + " " + time)
    

# Receiver's operation loop.
while True:
    try:
        conn, addr = s.accept()
        threading.Thread(target=handleClient, args=(conn,)).start()
    except socket.timeout:
        continue