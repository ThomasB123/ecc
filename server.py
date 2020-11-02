
# server is invokable as follows:
# python server.py serverip port
# e.g.: python server.py 127.0.0.1 12000
# would cause the server to listen
# on 127.0.0.1 (the local system) port number 12000

import sys
# used to take arguments from the command line
from socket import socket, AF_INET, SOCK_STREAM
# used to create TCP sockets
import pickle
# enables the sending and receiving of
# data types other than strings (arrays in this case)

if __name__ == "__main__":
    # when program is run directly
    serverIP = sys.argv[1]
    serverPort = int(sys.argv[2])
    # take command line arguments
    serverSocket = socket(AF_INET, SOCK_STREAM)
    # create a server socket
    serverSocket.bind((serverIP, serverPort))
    # bind the socket to an address
    serverSocket.listen(5)
    # allow up to 5 clients concurrently
    print("server running at {} on port {}".format(serverIP, serverPort))
    # inform user that the server is running
    keys = {}
    while True:
        # main program loop, wait for a request, and serve it
        connectionSocket, addr = serverSocket.accept()
        # accept connections from outside
        #connectionSocket.setblocking(False) # this breaks it for some reason
        # make sure socket does not block
        command = pickle.loads(connectionSocket.recv(4096))
        # receive up to 4096 bytes from the socket
        # this is plenty
        if command[0] == 'GET':
            # if client has sent a GET request
            connectionSocket.send(pickle.dumps(keys))
        elif command[0] == 'SET':
            keys[command[1]] = command[2]
            print(keys)
    # if server breaks out of its running loop
    # will only do this if there are no message boards defined
    connectionSocket.close()
    # close connectionSocket
    serverSocket.close()
    # close serverSocket
    # kill connections before server program finishes
    # last things to happen before server shuts down


'''
table: user ID, name, recepient, key
002, Bob, Alice, ...

Alice checks periodically for requests for communication with her

table: user ID, name, public key
for checking signatures later

flow chart diagram for message sequence. Alice, Server, Bob
do a message exchange diagram
check if Alice is online e.g.
ECDH, change key for every communication, look up protocol
'''