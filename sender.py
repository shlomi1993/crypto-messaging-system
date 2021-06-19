import socket, sys

# args
#TODO: check if argv[1] is exsist with try
Xname = sys.argv[1]  # 10.0.2.15 pc1
FILE_NAME = "messages"+Xname+".txt"



while (True):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sendMsg = input()

    addr = (serverIP, int(serverPort))
    s.sendto(sendMsg.encode('utf-8'), addr)

    data, addr = s.recvfrom(1024)
    reciveMsg = data.decode("utf-8")
    if (reciveMsg != 'ERROR!'):
        currentline = reciveMsg.split(",")
        print(currentline[1])
    else:
        print(reciveMsg)

    s.close()
