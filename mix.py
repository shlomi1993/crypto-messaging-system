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

number = int(sys.argv[1])
port = 4000 + number

# Open socket with client
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('', int(port)))

# def create_secret_key(self):
#     private_key = rsa.generate_private_key(public_exponent = 65537,
# 		key_size = 2048, backend = default_backend())
#     return private_key.private_bytes(encoding = serialization.Encoding.PEM,
# 		format = serialization.PrivateFormat.TraditionalOpenSSL,
#         encryption_algorithm = serialization.NoEncryption()).decode()

with open("sk" + str(number) + ".pem", "rb") as file:
	sk = load_pem_private_key(file.read(), password = None, backend = default_backend())

# Simulation:
with open("aliceMsgSimulation.txt", "rb") as file:
	data = file.read()
	# data = base64.b64encode(file.read()).decode()
# print(data.decode())
with open("pk" + str(number) + ".pem", "rb") as file2:
	pkey = file2.read()
	pk = load_pem_public_key(pkey, backend = default_backend())
message = b"Hello world"
ciphertext = pk.encrypt(message,
        padding.OAEP(
            mgf = padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None)
        )
print(ciphertext)
plaintext = sk.decrypt(ciphertext,
        padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None)
        )
print(plaintext)





doing = False
while True:

	time = datetime.now().strftime("%H:%M:%S")
	time_splitted = time.split(":")

	if (time_splitted[2] != "00"):
		doing = False

	elif (doing == False):
		doing = True
		print("send things")


	# data, addr = s.recvfrom(4096)
	# Recieve simulation
	# plaintext = sk.decrypt(data.decode(),
	#         padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()),
	#             algorithm = hashes.SHA256(),
	#             label = None)
	#         )
	# print(plaintext)



	# reciveMsg = str(data)
	# print("recive: " + reciveMsg + " from: ", addr)
	#
	# sendMsg = data.upper()
	# s.sendto(sendMsg, addr)
	# print("send: " + sendMsg + " to: ", addr)
	# #
	# if (parentIP != -1 and parentPort != -1):
	# 	sendMsg = ("check2")
	# 	f.sendto(sendMsg.encode('utf-8'),(parentIP, int(parentPort)))
	# 	print("send: " + sendMsg + " to: ", parentIP, int(parentPort))
	# 	data, addr = f.recvfrom(1024)
	# 	reciveMsg = str(data)
	# 	print("recive: " + reciveMsg + " from: ", addr)
		#f.close()
