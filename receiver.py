# Shlomi Ben-Shushan, 311408264, Ofir Ben-Ezra, 206073488

import socket, sys, base64
from cryptography.fernet import Fernet
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

BUFFER_SIZE = 20480

# Get arguments
password = sys.argv[1].encode()
salt = sys.argv[2].encode()
try:
	port = int(sys.argv[3])
except:
    print("Cannot parse given port.")
    exit(-1)

# Function that generates a symmetric key.
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

# Generate symmetric key.
k = genSymmetricKey(password, salt)

# Create a socket, bind and listen.
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', port))
s.listen(5)

# Receiver's operation loop.
while True:
    conn, addr = s.accept()
    conn.settimeout(1)
    data = conn.recv(BUFFER_SIZE)
    if len(data) > 0:
        plaintext = k.decrypt(data).decode()
        time = datetime.now().strftime("%H:%M:%S")
        print(plaintext + " " + time)