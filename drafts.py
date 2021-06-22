# with open("pk" + str(number) + ".pem", "rb") as file2:
# 	pkey = file2.read()
# 	pk = load_pem_public_key(pkey, backend = default_backend())
# message = b"Hello world"
# ciphertext = pk.encrypt(message,
#         padding.OAEP(
#             mgf = padding.MGF1(algorithm = hashes.SHA256()),
#             algorithm = hashes.SHA256(),
#             label = None)
#         )
# print("CIPHER")
# print(ciphertext)
# plaintext = sk.decrypt(ciphertext,
#         padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()),
#             algorithm = hashes.SHA256(),
#             label = None)
#         )
# print(plaintext)



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