
# client is invokable as follows:
# python client.py serverip port
# e.g.: python client.py 127.0.0.1 12000
# would cause the client to attempt to connect
# to a server already listening
# on 127.0.0.1 (the local system) port number 12000

import time

import sys
# used to take arguments from the command line
import os.path
from os import path
# used to check if log file already exists or not
from socket import socket, AF_INET, SOCK_STREAM
# used to create TCP sockets
from datetime import datetime
# used for log file entries
import pickle
# enables the sending and receiving of
# data types other than strings (arrays in this case)
import select
# used for request timeout checking

def binary(num): # convert denary number to binary
    out = []
    while num > 0:
        if num % 2 == 1:
            num -= 1
            out.append(1)
        else:
            out.append(0)
        num /= 2
    return out

def move(xa,ya,xb,yb):
    if [xa,ya] == [xb,yb]:
        # doubling a point
        m = ((3*xa**2+a)*pow(2*ya,p-2,p)) % p # (3x^2+a)/(2y) % p
    else:
        # adding two points
        m = ((yb-ya)*pow(xb-xa,p-2,p)) % p # (yb-ya)/(xb-xa) % p
    xd = (m**2 -xa-xb) % p
    yd = (m*(xa-xd) - ya) % p
    return xd,yd

def K(start,k):
    points = [start]
    bina = binary(k)
    for i in range(len(bina)):#-bina.index(1)):
        points.append(move(points[-1][0],points[-1][1],points[-1][0],points[-1][1])) # double
    index = bina.index(1) # find first occurence of 1 in the binary representation
    out = points[index] # start with smallest multiple of g
    for i in range(index+1,len(bina)): # count up from the smallest multiple
        if bina[i] == 1:
            out = move(out[0],out[1],points[i][0],points[i][1])
    return out

def montgomery(a,b): # convert from montgomery to short weierstrass
    # a = (3 - a^2)/(3b^2) and b = (2a^3 - 9a)/(27b^3)
    return (3-a**2)*pow(3*b**2,p-2,p),(2*a**3-9*a)*pow(27*b**3,p-2,p)

def edwards(d): # convert from edwards to short weierstrass
    # a = 2(1 + d)/(1 - d) and b = 4/(1 - d)
    return montgomery(2*(1+d)*pow(1-d,p-2,p),4*pow(1-d,p-2,p))

# public parameters: p,a,b,g

# Curve25519
p = 2**255 - 19
a,b = montgomery(486662,1)
g = (9,14781619447589544791020593568409986887264606134616475288964881837755586237401)

def sendKey():
    clientSocket = socket(AF_INET, SOCK_STREAM)
    # create socket
    clientSocket.connect((serverIP, serverPort))
    # connect to server
    clientSocket.setblocking(False)
    # make sure socket is not blocking
    clientSocket.send(pickle.dumps(['SET',name, publicKey]))
    # send data to server
    # using array to send multiple arguments
    clientSocket.close()
    # close socket
    print('Sent Public Key to server')

def getKeys():
    clientSocket = socket(AF_INET, SOCK_STREAM)
    # create socket
    clientSocket.connect((serverIP, serverPort))
    # connect to server
    clientSocket.setblocking(False)
    # make sure socket is not blocking
    clientSocket.send(pickle.dumps(['GET']))
    # send data to server
    # using array to send multiple arguments
    ready = select.select([clientSocket], [], [], 10)
    if ready[0]:
        # data received before timeout
        messages = pickle.loads(clientSocket.recv(4096))
        # receive up to 4096 bytes from the socket
    else:
        # Timeout expired
        # Response not received in 10 seconds
        print('GET_MESSAGES failed!')
        return 'ERROR'
    clientSocket.close()

    print(messages)
    if otherName in messages:
        key = K(messages[otherName],k)
        print('Shared Key:',key[0])
        return True
    else:
        return False


if __name__ == "__main__":
    # when program is run directly
    serverIP = sys.argv[1]
    serverPort = int(sys.argv[2])
    name = sys.argv[3]
    # take command line arguments
    otherName = 'Bob' if name == 'Alice' else 'Alice'
    # Change private keys here
    #####################################
    # private keys  2 <= ka,kb <= p-2
    k = 2**210-1 if name == 'Alice' else 2**200-1 # private key
    #####################################
    publicKey = K(g,k)
    boards = sendKey()
    other = False
    while not other:
        other = getKeys()
        if not other:
            time.sleep(5)

# implement ephemeral Diffie Hellman