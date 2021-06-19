import socket, sys

#args
# windows: myPort = 12345 parentIP = 10.0.2.15 ParentPort= 5555 ipsFileName = ips.txt
# pc1: myPort = 5555, parentIP = -1, ParentPort= -1, ipsFileName =parent.txt

myPort = sys.argv[1]
parentIP = sys.argv[2]
parentPort = sys.argv[3]
ipsFileName = sys.argv[4]

#Open socket with client
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('', int(myPort)))

#Open socket with parent
if (parentIP != -1 and parentPort != -1):
	f = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:
	data, addr = s.recvfrom(1024)
	reciveMsg = str(data)
	print("recive: " + reciveMsg + " from: ", addr)
	#
	sendMsg = data.upper()
	s.sendto(sendMsg, addr)
	print("send: " + sendMsg + " to: ", addr)
	#
	if (parentIP != -1 and parentPort != -1):
		sendMsg = ("check2")
		f.sendto(sendMsg.encode('utf-8'),(parentIP, int(parentPort)))
		print("send: " + sendMsg + " to: ", parentIP, int(parentPort))
		data, addr = f.recvfrom(1024)
		reciveMsg = str(data)
		print("recive: " + reciveMsg + " from: ", addr)
		#f.close()
