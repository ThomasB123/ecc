
# run as follows:
# python -m Pyro4.naming
# python server.py
# python client.py

import Pyro4
from Cryptodome.Cipher import AES
import base64 # built in
import hashlib # built in
import secrets # built in
import os
import os.path # used for file sending

def move(xa,ya,xb,yb):
    if xa is None:
        # 0 + point2 = point2
        return xb,yb
    if xb is None:
        # point1 + 0 = point1
        return xa,ya
    if form == 0: # Short Weierstrass form
        if [xa,ya] == [xb,yb]: # doubling a point
            m = ((3*xa**2+a)*inverse(p,2*ya)) # (3x^2+a)/(2y)
        else: # adding two points
            m = ((yb-ya)*inverse(p,xb-xa)) # (yb-ya)/(xb-xa)
        xd = (m**2 -xa-xb)
    elif form == 1: # Montgomery form
        if [xa,ya] == [xb,yb]: # doubling a point
            m = (3*xa**2+2*a*xa+1)*inverse(p,2*b*ya) # (3x^2+2ax+1)/(2by)
        else: # adding two points
            m = (yb-ya)*inverse(p,xb-xa) # (yb-ya)/(xb-xa)
        xd = b*m**2 -a-xa-xb
    yd = m*(xa-xd) - ya # flipped in x axis here
    return xd%p,yd%p

def K(start,k): # calculare k*start
    # k is integer and start is point
    result = (None,None)
    addend = start
    while k:
        if k & 1:
            result = move(result[0],result[1],addend[0],addend[1]) # add
        addend = move(addend[0],addend[1],addend[0],addend[1]) # double
        k >>= 1
    return result

def inverse(a,b):
    # find b^{-1} mod a
    if b < 0:
        return a - inverse(a,-b)
    r = {-1:a,0:b}
    s = {-1:1,0:0}
    t = {-1:0,0:1}
    q = {}
    i = 0
    while r[i] != 0:
        i += 1
        r[i] = r[i-2]%r[i-1]
        q[i] = r[i-2]//r[i-1]
        s[i] = s[i-2]-q[i]*s[i-1]
        t[i] = t[i-2]-q[i]*t[i-1]
    return t[i-1]%a

def newContact():
    publicKeys = server.sendKeys()
    if publicKeys == {} or len(publicKeys) == 1:
        print('Nobody is currently available')
    else:
        print('You can establish a key with:')
        i = 1
        people = []
        for x in publicKeys:
            if x != name: # so you can't send a message to yourself
                people.append(x)
                print('{}. {}'.format(i,x))
                i += 1
        keyChoice = '0'
        while int(keyChoice) not in range(1,len(people)+1):
            keyChoice = input('Choose a person > ')
            try:
                int(keyChoice) # check for bad input
            except:
                keyChoice = '0'
        person = people[int(keyChoice)-1]
        pubPriv = K(publicKeys[person],privateKey)
        pubPrivh = K(pubPriv,h) # cofactor h, prevents small subgroup attacks
        sharedKey = pubPrivh[0] # only use x-coordinate for key
        sharedKeys[person] = sharedKey
        if verbose:
            print('Your shared key is calculated by h*d*Q, where h is the cofactor, d is your private key, and Q is {}\'s public key'.format(person))
            print('{}\'s public key is {}, multiplying by your private key gives {}'.format(person,publicKeys[person],pubPriv))
            print('Then multiplying this by the cofactor h={} gives {}'.format(h,pubPrivh))
            print('Therefore, your shared key with {} is {}'.format(person,sharedKey))
        else:
            print('Your shared key with {} is 0x{:x}'.format(person,sharedKey))

def viewContacts():
    if sharedKeys == {}:
        print('You don\'t have any contacts yet')
    else:
        if len(sharedKeys) == 1:
            print('You have {} contact:'.format(len(sharedKeys)))
        else:
            print('You have {} contacts:'.format(len(sharedKeys)))
        for i in sharedKeys:
            print(i)

def sendMessage():
    if sharedKeys == {}:
        print('You need to add a contact first')
    else:
        print('You can send a message to:')
        i = 1
        contacts = []
        for x in sharedKeys:
            contacts.append(x)
            print('{}. {}'.format(i,x))
            i += 1
        keyChoice = '0'
        while int(keyChoice) not in range(1,len(contacts)+1):
            keyChoice = input('Choose a person > ')
            try:
                int(keyChoice) # check for bad input
            except:
                keyChoice = '0'
        recipient = contacts[int(keyChoice)-1]
        message = input('What would you like to say to {}? > '.format(recipient))
        encoded = message.encode('utf-8')
        key = hashlib.sha256(int.to_bytes(sharedKeys[recipient],32,'big')).digest() # convert ecc key to 32 bytes
        cipher = AES.new(key,AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext,tag = cipher.encrypt_and_digest(encoded)
        # send signature with text message
        hashed = hashlib.sha512(encoded)
        integer = int.from_bytes(hashed.digest(),'big')
        e = integer >> (integer.bit_length() - n.bit_length()) # hash of message, truncated
        k = generator.randrange(n//2,n-1) # select random integer k in interval [1,n-1]
        r = K(g,k)[0] % n # compute x coordinate of kg mod n (g is base point), if r = 0, generate new k
        s = inverse(n,k)*(e+privateKey*r) % n # compute s = k^-1{e + privateKey(r)} mod n
        server.receiveMessage(recipient,name,nonce,ciphertext,tag,r,s) # encrypt here
        if verbose:
            print('Use shared key to encrypt your message to {}'.format(recipient))
            print('Truncated hash of message: e = {}'.format(e))
            print('Select random k, calculate r = kG = {}'.format(r))
            print('s = (e+key*r)/k = {}'.format(s))
            print('Signature is pair (r,s)')
        print('Message sent to {}'.format(recipient))

def checkMessages():
    messages = server.checkMessages(name)
    if messages == []:
        print('There are no messages for you {}'.format(name))
    else:
        if len(messages) == 1:
            print('You have {} message:'.format(len(messages)))
        else:
            print('You have {} messages:'.format(len(messages)))
        for i in messages:
            sender = i[1]
            if sender not in sharedKeys:
                print('You must add {} as a contact to read this message'.format(sender))
            else:
                nonce = base64.b64decode(i[2]['data']) # decrypt here
                ciphertext = base64.b64decode(i[3]['data'])
                tag = base64.b64decode(i[4]['data'])
                key = hashlib.sha256(int.to_bytes(sharedKeys[sender],32,'big')).digest() # convert ecc key to 32 bytes
                cipher = AES.new(key,AES.MODE_EAX,nonce=nonce)
                try:
                    plaintext = cipher.decrypt(ciphertext).decode()
                    cipher.verify(tag)
                    r = i[5]
                    s = i[6]
                    publicKeys = server.sendKeys()
                    publicKey = publicKeys[sender] # obtain A's public key Q
                    # verify that r and s are integers in interval [1,n-1]
                    w = inverse(n,s) # compute w = s^-1 mod n
                    message_hash = hashlib.sha512(plaintext.encode('utf-8'))
                    integer = int.from_bytes(message_hash.digest(),'big') # compute hash of message h(m), as bytes object
                    e = integer >> (integer.bit_length() - n.bit_length()) # discard rightmost bits to truncate hash
                    u1 = e*w % n # compute u1 = h(m)w mod n
                    u2 = r*w % n # compute u2 = rw mod n
                    u1G = K(g,u1)
                    u2Q = K(publicKey,u2)
                    v = move(u1G[0],u1G[1],u2Q[0],u2Q[1])[0] % n # compute u1P + u2Q = (x0,y0) and v = x0 mod n
                    r = r % n
                    if verbose:
                        print('Use (r,s) signature pair, sent by {}'.format(sender))
                        print('Use shared key to decrypt message from {}'.format(sender))
                        print('Truncated hash of message: e = {}'.format(e))
                        print('v = (e/s)*G + (r/s)*Q = {}'.format(v))
                        print('r = {}'.format(r))
                        if v == r:
                            print('v == r, so the signature is valid')
                        else:
                            print('v != r, so the signature is not valid')
                    if v == r:
                        print('{} says {}, and the signature is authentic'.format(sender,plaintext))
                    else:
                        print('{} says {}, but the signature is not authentic'.format(sender,plaintext))
                    server.deleteMessage(i[0]) # delete message from server once read, regardless of signature verification
                except ValueError:
                    print('Your shared key with {} is incorrect'.format(sender))

def sendSignature(): # ECDSA algorithm
    message = b'Hello!' # verify signatures with simple message
    message_hash = hashlib.sha512(message) # to ensure 512 bit hashes, so always larger than n when truncating
    integer = int.from_bytes(message_hash.digest(),'big') # hash value as an integer
    e = integer >> (integer.bit_length() - n.bit_length()) # hash of message, truncated to size of n
    k = generator.randrange(n//2,n-1) # select random integer k in interval [1,n-1]. Demo why this breaks when k is constant
    r = K(g,k)[0] % n # compute x coordinate of kg mod n (g is base point), if r = 0, generate new k
    s = inverse(n,k)*(e+privateKey*r) % n # compute s = k^-1{e + privateKey(r)} mod n
    server.receiveSignature(name,r,s) # signature for message m is (r,s)
    if verbose:
        print('Truncated hash of message: e = {}'.format(e))
        print('Select random k, calculate r = kG = {}'.format(r))
        print('s = (e+key*r)/k = {}'.format(s))
        print('Signature is pair (r,s)')
    print('Signature sent.')

def checkSignature():
    signatures = server.sendSignatures()
    if signatures == {} or (len(signatures) == 1 and name in signatures):
        print('There are no signatures to check')
    else:
        print('You can check the signature of:')
        i = 1
        people = []
        for x in signatures:
            if x != name: # so you can't send a message to yourself
                people.append(x)
                print('{}. {}'.format(i,x))
                i += 1
        keyChoice = '0'
        while int(keyChoice) not in range(1,len(people)+1):
            keyChoice = input('Choose a person > ')
            try:
                int(keyChoice) # check for bad input
            except:
                keyChoice = '0'
        person = people[int(keyChoice)-1]
        [r,s] = signatures[person]
        publicKeys = server.sendKeys()
        publicKey = publicKeys[person] # obtain A's public key Q
        # verify that r and s are integers in interval [1,n-1]
        message = b'Hello!' # simple test message, for signature verification
        message_hash = hashlib.sha512(message)
        integer = int.from_bytes(message_hash.digest(),'big') # compute hash of message h(m), as an integer
        e = integer >> (integer.bit_length() - n.bit_length()) # discard rightmost bits to truncate hash
        w = inverse(n,s) # compute w = s^-1 mod n
        u1 = e*w % n # compute u1 = h(m)w mod n
        u2 = r*w % n # compute u2 = rw mod n
        u1G = K(g,u1)
        u2Q = K(publicKey,u2)
        v = move(u1G[0],u1G[1],u2Q[0],u2Q[1])[0] % n # compute u1P + u2Q = (x0,y0) and v = x0 mod n
        r = r % n
        if verbose:
            print('Use (r,s) signature pair, sent by {}'.format(person))
            print('Truncated hash of message: e = {}'.format(e))
            print('v = (e/s)*G + (r/s)*Q = {}'.format(v))
            print('r = {}'.format(r))
            if v == r:
                print('v == r, so the signature is valid')
            else:
                print('v != r, so the signature is not valid')
        if v == r:
            print('Signature Accepted!')
        else:
            print('Signature Error')

def sendFile():
    if sharedKeys == {}:
        print('You need to add a contact first')
    else:
        print('You can send a file to:')
        i = 1
        contacts = []
        for x in sharedKeys:
            contacts.append(x)
            print('{}. {}'.format(i,x))
            i += 1
        keyChoice = '0'
        while int(keyChoice) not in range(1,len(contacts)+1):
            keyChoice = input('Choose a person > ')
            try:
                int(keyChoice) # check for bad input
            except:
                keyChoice = '0'
        recipient = contacts[int(keyChoice)-1]
        fileName = ''
        while not os.path.isfile(fileName):
            fileName = input('Enter file name > ')
        key = hashlib.sha256(int.to_bytes(sharedKeys[recipient],32,'big')).digest() # convert shared ecc key to 32 bytes
        cipher = AES.new(key,AES.MODE_CBC)
        nsz = len(fileName.encode('utf-8')) # name size in bytes
        fsz = os.path.getsize(fileName) # file size in bytes
        iv = cipher.iv
        sz = 256
        encrypted = []
        fileNameBuffer = fileName
        if len(fileName) % 16 != 0:
            fileNameBuffer += ' ' * (16-len(fileName)%16)
        nameEncrypted = cipher.encrypt(fileNameBuffer.encode('utf-8'))
        with open(fileName,'rb') as fin:
            while True:
                data = fin.read(sz)
                i = len(data)
                if i == 0:
                    break
                elif i % 16 != 0:
                    data += bytearray(' ','utf-8') * (16-i%16) # padded with spaces (in byte form)
                encd = cipher.encrypt(data)
                encrypted.append(encd)
        BLOCK_SIZE = 251 # 251 bit chunks
        file_hash = hashlib.sha512() # to ensure 512 bit hashes, so always larger than n when truncating
        with open(fileName,'rb') as f:
            fb = f.read(BLOCK_SIZE)
            while len(fb) > 0:
                file_hash.update(fb)
                fb = f.read(BLOCK_SIZE)
        integer = int.from_bytes(file_hash.digest(),'big')
        e = integer >> (integer.bit_length() - n.bit_length()) # hash of message, truncated
        k = generator.randrange(n//2,n-1) # select random integer k in interval [1,n-1]
        r = K(g,k)[0] % n # compute x coordinate of kg mod n (g is base point), if r = 0, generate new k
        s = inverse(n,k)*(e+privateKey*r) % n # compute s = k^-1{e + privateKey(r)} mod n
        server.receiveFile(recipient,name,nameEncrypted,nsz,encrypted,fsz,iv,r,s)
        if verbose:
            print('Use shared key to encrypt your file to {}'.format(recipient))
            print('Truncated hash of message: e={}'.format(e))
            print('Select random k, calculate r=kG={}'.format(r))
            print('s=(e+key*r)/k={}'.format(s))
            print('Signature is pair (r,s)')
        print('File sent to {}'.format(recipient))

def checkFiles():
    files = server.sendFiles(name)
    if files == []:
        print('There are no files for you {}'.format(name))
    else:
        if len(files) == 1:
            print('You have {} file:'.format(len(files)))
        else:
            print('You have {} files:'.format(len(files)))
        for i in files:
            sender = i[1]
            if sender not in sharedKeys:
                print('You must add {} as a contact to read this file'.format(sender))
            else:
                fileName = base64.b64decode(i[2]['data'])
                nsz = i[3] # file name size in bytes
                fileContent = i[4]
                fsz = i[5] # file size in bytes
                iv = base64.b64decode(i[6]['data'])
                r = i[7]
                s = i[8]
                key = hashlib.sha256(int.to_bytes(sharedKeys[sender],32,'big')).digest()
                cipher = AES.new(key,AES.MODE_CBC,iv)
                sz = 256
                try:
                    plainName = cipher.decrypt(fileName)[:nsz].decode() # must decode in same order as encoded, since using CBC
                    # trim padding before decoding
                    if not os.path.exists(name):
                        os.makedirs(name)
                    with open(os.path.join(name,plainName),'wb') as fout: # write in binary mode
                        for x in fileContent:
                            data = base64.b64decode(x['data'])
                            #print(data)
                            text = cipher.decrypt(data)#.decode()
                            if fsz > len(text):
                                fout.write(text)
                            else:
                                fout.write(text[:fsz]) # remove padding on last block
                            fsz -= len(text)
                    # signature check
                    publicKeys = server.sendKeys()
                    publicKey = publicKeys[sender] # obtain A's public key Q
                    # verify that r and s are integers in interval [1,n-1]
                    BLOCK_SIZE = 251 # 251 bit chunks
                    file_hash = hashlib.sha512() # to ensure 512 bit hashes, so always larger than n when truncating
                    with open(os.path.join(name,plainName),'rb') as f:
                        fb = f.read(BLOCK_SIZE)
                        while len(fb) > 0:
                            file_hash.update(fb)
                            fb = f.read(BLOCK_SIZE)
                    integer = int.from_bytes(file_hash.digest(),'big')
                    e = integer >> (integer.bit_length() - n.bit_length()) # hash of message, truncated
                    w = inverse(n,s) # compute w = s^-1 mod n
                    u1 = e*w % n # compute u1 = h(m)w mod n
                    u2 = r*w % n # compute u2 = rw mod n
                    u1G = K(g,u1)
                    u2Q = K(publicKey,u2)
                    v = move(u1G[0],u1G[1],u2Q[0],u2Q[1])[0] % n # compute u1P + u2Q = (x0,y0) and v = x0 mod n
                    r = r % n
                    if verbose:
                        print('Use (r,s) signature pair, sent by {}'.format(sender))
                        print('Use shared key to decrypt file from {}'.format(sender))
                        print('Truncated hash of message: e = {}'.format(e))
                        print('v = (e/s)*G + (r/s)*Q = {}'.format(v))
                        print('r = {}'.format(r))
                        if v == r:
                            print('v == r, so the signature is valid')
                        else:
                            print('v != r, so the signature is not valid')
                    if v == r:
                        print('{} sent you a file called {}, and the signature is authentic'.format(sender,plainName))
                    else:
                        print('{} sent you a file called {}, but the signature is not authentic'.format(sender,plainName))
                    server.deleteFile(i[0])
                except:
                    print('Your shared key with {} is incorrect'.format(sender))

if __name__ == "__main__":
    # public parameters: p,a,b,g,n,h

    # Curve25519
    # form = {0:'Short Weierstrass', 1:'Montgomery'}
    form = 1 # by^2 = x^3 + ax^2 + x
    p = 2**255 - 19 # prime, size of finite field
    a = 486662 # coefficients of curve
    b = 1 # coefficients of curve
    g = (9,14781619447589544791020593568409986887264606134616475288964881837755586237401) # base point
    n = 2**252 + 27742317777372353535851937790883648493 # (prime) order of subgroup
    h = 2**3 # cofactor of subgroup, h = (number of points on curve / n)
    
    server = Pyro4.Proxy("PYRONAME:server")
    name = ''
    verbose = True
    while name == '':
        name = input('What is your name? > ').strip()
    sharedKeys = {}
    generator = secrets.SystemRandom()
    privateKey = generator.randrange(n//2,n-1) # {1,...,n-1} where n is the order of the subgroup
    publicKey = K(g,privateKey)
    server.receiveKey(name,publicKey)
    
    while True:

        print('''
What would you like to do {}?
1. Add a new contact
2. View your contacts
3. Send signature
4. Check a signature
5. Send a message
6. Check for messages
7. Send a file
8. Check for files
9. Toggle verbose mode
q. Quit
        '''.format(name))

        validChoice = False
        while not validChoice:
            validChoice = True
            choice = input('Your choice > ')
            if choice == '1':
                newContact()
            elif choice == '2':
                viewContacts()
            elif choice == '3':
                sendSignature()
            elif choice == '4':
                checkSignature()
            elif choice == '5':
                sendMessage()
            elif choice == '6':
                checkMessages()
            elif choice == '7':
                sendFile()
            elif choice == '8':
                checkFiles()
            elif choice == '9':
                if verbose:
                    verbose = False
                    print('Verbose mode off')
                else:
                    verbose = True
                    print('Verbose mode on')
            elif choice == 'q' or choice == 'Q':
                print('Goodbye', name)
                quit()
            else:
                validChoice = False

# implement ephemeral Diffie Hellman

# use user delay in future development?
# Design your own random number algorithm based on e.g. user delay on inputs.
# How many random bits do you need? How long will it take.

# sign two files with same key and same k, then calculate private key and sign third document with it, ie demo breaking ECDSA like Sony

# also look at what specifically the secrets module uses to generate randomness

# clear up code a bit, parameterise more and use better variable names
# change aes type for message sending?

# timing attacks, how many 1s and most significant 1 in binary
# run with different key size settings and see how long it takes to do calculations

'''
presentation is 10 minutes
about how well you communicate not how good your project is
explain whar your project is, what you've done so far and what you have left to do
don't use too much technical language
give intuitive definitions, only define ECDLP, not also ECDHP
7 slides max, gives 1 min 25 secs per slide
say that various things make curve safe, here they are but I don't have time to go through them, maybe most intuitive one
relating to RSA is good since can assume audience knowledge of RSA
'''
