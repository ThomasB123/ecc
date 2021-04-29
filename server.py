
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
        print()
        print('New public key received from {}: (0x{:x}, 0x{:x})'.format(name,key[0],key[1]))

    def sendKeys(self,name):
        if name != None:
            print()
            print('Sending list of public keys to {}'.format(name))
        return keys

    def receiveMessage(self,to,from_,nonce,ciphertext,tag,r,s): # recipient, sender, content
        x = uuid.uuid1() # unique identifier of message
        messages[x.hex] = [to,from_,nonce,ciphertext,tag,r,s]
        print()
        print('Received new message from {} to {}'.format(from_,to))
        print('Nonce (base64): {}'.format(nonce['data']))
        print('Ciphertext (base64): {}'.format(ciphertext['data']))
        print('Signature pair (r,s): (0x{:x}, 0x{:x})'.format(r,s))

    def checkMessages(self,to):
        out = []
        for i in messages:
            if messages[i][0] == to: # if message is meant for person
                add = [i]
                for x in messages[i][1:]: # add all parts except 'to'
                    add.append(x)
                out.append(add)
        print()
        if len(out) == 0:
            print('There are no messages for {}'.format(to))
        if len(out) == 1:
            print('There is 1 message for {}'.format(to))
        if len(out) > 1:
            print('There are {} messages for {}'.format(len(out),to))
        return out

    def deleteMessage(self,x):
        messages.pop(x)
    
    def receiveSignature(self,from_,r,s):
        signatures[from_] = [r,s]
        print()
        print('Received new signature from {}'.format(from_))
        print('Signature pair (r,s): (0x{:x}, 0x{:x})'.format(r,s))

    def sendSignatures(self,name):
        print()
        print('Sending list of signatures to {}'.format(name))
        return signatures
    
    def receiveFile(self,to,from_,nameEncrypted,nsz,encrypted,fsz,iv,r,s):
        x = uuid.uuid1()
        files[x.hex] = [to,from_,nameEncrypted,nsz,encrypted,fsz,iv,r,s]
        print()
        print('Received new file from {} to {}'.format(from_,to))
        print('Encrypted file name (base64): {}'.format(nameEncrypted['data']))
        print('Encrypted file data (base64), packet 1 of {}: {}'.format(len(encrypted),encrypted[0]['data']))
        print('Signature pair (r,s): (0x{:x}, 0x{:x})'.format(r,s))
    
    def sendFiles(self,to):
        out = []
        for i in files:
            if files[i][0] == to:
                add = [i]
                for x in files[i][1:]:
                    add.append(x)
                out.append(add)
        print()
        if len(out) == 0:
            print('There are no files for {}'.format(to))
        if len(out) == 1:
            print('There is 1 file for {}'.format(to))
        if len(out) > 1:
            print('There are {} files for {}'.format(len(out),to))
        return out
    
    def deleteFile(self,x):
        files.pop(x)

if __name__ == "__main__":

    daemon = Pyro4.Daemon() # make a Pyro daemon
    ns = Pyro4.locateNS() # find the name server
    uri = daemon.register(server) # register the JustHungry class as a Pyro object
    ns.register('server', uri) # register the object with a name in the name server
    keys = {}
    messages = {}
    signatures = {}
    files = {}
    print("Ready.")
    daemon.requestLoop() # start the event loop of the server to wait for calls
