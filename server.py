
# run as follows:
# python -m Pyro4.naming
# python server.py
# python client.py

import Pyro4
import uuid

@Pyro4.expose
class server(object):
    
    def receiveKey(self,name,key):
        keys[name] = key
        print(keys)

    def sendKeys(self):
        return keys

    def checkOnline(self):
        return None

    def receiveMessage(self,to,from_,nonce,ciphertext,tag): # recipient, sender, content
        x = uuid.uuid1() # unique identifier of message
        messages[x.hex] = [to,from_,nonce,ciphertext,tag]
        print(messages)
        return None

    def checkMessages(self,to):
        global messages
        out = []
        for i in messages:
            if messages[i][0] == to:
                add = [i]
                for x in messages[i][1:]:
                    add.append(x)
                out.append(add)
        return out

    def deleteMessage(self,x):
        messages.pop(x)

if __name__ == "__main__":

    daemon = Pyro4.Daemon() # make a Pyro daemon
    ns = Pyro4.locateNS() # find the name server
    uri = daemon.register(server) # register the JustHungry class as a Pyro object
    ns.register('server', uri) # register the object with a name in the name server
    keys = {}
    messages = {}
    print("Ready.")
    daemon.requestLoop() # start the event loop of the server to wait for calls
    
# client = Pyro4.Proxy('PYRONAME:name')
# if want to do a check alive thing

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

This is end to end encryption, the server should not be able to read messages
'''