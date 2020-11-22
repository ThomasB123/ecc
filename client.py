
# run as follows:
# python -m Pyro4.naming
# python server.py
# python client.py

import sympy # used isprime() function
import Pyro4
from Cryptodome.Cipher import AES
import base64 # built in
import hashlib # built in
import secrets # built in

def move(xa,ya,xb,yb):
    if xa is None:
        # 0 + point2 = point2
        return xb,yb
    if xb is None:
        # point1 + 0 = point1
        return xa,ya
    if form == 0: # Short Weierstrass
        if [xa,ya] == [xb,yb]: # doubling a point
            m = ((3*xa**2+a)*inverse(p,2*ya)) # (3x^2+a)/(2y)
        else: # adding two points
            m = ((yb-ya)*inverse(p,xb-xa)) # (yb-ya)/(xb-xa)
        xd = (m**2 -xa-xb)
    elif form == 1: # Montgomery
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
        sharedKey = K(publicKeys[person],privateKey)[0] # only use x-coordinate for key
        sharedKeys[person] = sharedKey
        print('Your shared key with {} is {}'.format(person,sharedKey))

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
        key = hashlib.sha256(int.to_bytes(sharedKeys[recipient],32,'big')).digest() # convert ecc key to 32 bytes
        cipher = AES.new(key,AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext,tag = cipher.encrypt_and_digest(message.encode('utf8'))
        server.receiveMessage(recipient,name,nonce,ciphertext,tag) # encrypt here

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
                print('You don\'t have a key with {} yet'.format(sender))
            else:
                nonce = base64.b64decode(i[2]['data']) # decrypt here
                ciphertext = base64.b64decode(i[3]['data'])
                tag = base64.b64decode(i[4]['data'])
                key = hashlib.sha256(int.to_bytes(sharedKeys[sender],32,'big')).digest() # convert ecc key to 32 bytes
                cipher = AES.new(key,AES.MODE_EAX,nonce=nonce)
                try:
                    plaintext = cipher.decrypt(ciphertext).decode()
                    cipher.verify(tag)
                    print('{} says {}'.format(sender,plaintext))
                    server.deleteMessage(i[0])
                except ValueError:
                    print('Your key is incorrect')

def sendSignature():
    k = generator.randrange(1,n-1) # select random integer k in interval [1,n-1]
    r = K(g,k)[0] % n # compute x coordinate of kg mod n (g is base point), if r = 0, generate new k
    message = 'Hello!'
    encoded = message.encode('utf8')
    hashed = hashlib.sha512(encoded)
    integer = int.from_bytes(hashed.digest(),'big')
    e = integer >> (integer.bit_length() - n.bit_length())
    #e = (integer % n) //10# hash of message. truncated?
    print('e=hash(m):\n',e)
    # compute k^-1 mod n
    print('k*k^-1',inverse(n,k)*k%n) # extended euclidian algorithm, check that k/k = 1
    s = inverse(n,k)*(e+privateKey*r) % n # compute s = k^-1{e + privateKey(r)} mod n
    print('r=kG:\n',r)
    print('s=(e+key*r)/k:\n',s)
    server.receiveSignature(name,r,s) # signature for message m is (r,s)
    '''
    # ask for file here instead
    file = './test.txt'
    BLOCK_SIZE = 65536
    file_hash = hashlib.sha256()
    with open(file,'rb') as f:
        fb = f.read(BLOCK_SIZE)
        while len(fb) > 0:
            file_hash.update(fb)
            fb = f.read(BLOCK_SIZE)
    print(file_hash.digest()) # hash value as a bytes object
    # then send AES encrypted file using shared key?
    '''

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
        print('s:\n',s)
        publicKeys = server.sendKeys()
        publicKey = publicKeys[person] # obtain A's public key Q
        # verify that r and s are integers in interval [1,n-1]
        w = inverse(n,s) # compute w = s^-1 mod n
        message = 'Hello!'
        encoded = message.encode('utf8')
        hashed = hashlib.sha512(encoded)
        integer = int.from_bytes(hashed.digest(),'big')
        e = integer >> (integer.bit_length() - n.bit_length()) # discard righmost bits to truncate hash
        #e = (integer % n) // 10# compute hash of message h(m)
        print('e=hash(m):\n',e)
        u1 = e*w % n # compute u1 = h(m)w mod n
        u2 = r*w % n # compute u2 = rw mod n
        u1G = K(g,u1)
        u2Q = K(publicKey,u2)
        v = move(u1G[0],u1G[1],u2Q[0],u2Q[1])[0] % n # compute u1P + u2Q = (x0,y0) and v = x0 mod n
        r = r % n
        print('v=(e/s)G+(r/s)key:\n',v)
        print('r:\n',r)
        print('v == r ?:',v==r)
        if v == r:
            print('Signature Accepted!')
        else:
            print('Signature Error')
        return v == r # accept signature iff v = r

if __name__ == "__main__":
    # public parameters: p,a,b,g,n,h

    # Curve25519
    # form = {0:'Short Weierstrass', 1:'Montgomery', 2:'Edwards'}
    form = 1 # by^2 = x^3 + ax^2 + x
    p = 2**255 - 19 # prime, size of finite field
    a = 486662 # coefficients of curve
    b = 1 # coefficients of curve
    g = (9,14781619447589544791020593568409986887264606134616475288964881837755586237401) # base point
    n = 2**252 + 27742317777372353535851937790883648493 # (prime) order l
    h = 2**3 # cofactor
    '''
    # secp256k1
    form = 0 # y^2 = x^3 + ax + b
    p = 2**256 - 2**32 - 977
    a = 0
    b = 7
    g = (55066263022277343669578718895168534326250603453777594175500187360389116729240,32670510020758816978083085130507043184471273380659243275938904335757337482424)
    n = 2**256 - 432420386565659656852420866394968145599
    h = 1
    '''
    server = Pyro4.Proxy("PYRONAME:server")
    name = ''
    while name == '':
        name = input('What is your name? > ').strip()
    sharedKeys = {}
    generator = secrets.SystemRandom()
    privateKey = generator.randrange(1,n-1) # {1,...,n-1} where n is the order of the subgroup
    publicKey = K(g,privateKey)
    server.receiveKey(name,publicKey)
    
    while True:

        print('''
What would you like to do {}?
1. Add a new contact
2. View your contacts
3. Send a message
4. Check my messages
5. Send signature
6. Check a signature
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
                sendMessage()
            elif choice == '4':
                checkMessages()
            elif choice == '5':
                sendSignature()
            elif choice == '6':
                checkSignature()
            else:
                validChoice = False

# implement ephemeral Diffie Hellman
# cofactor h used to calculate P = h(my private)(other public)
# provides efficient resistance to attacks such as small subgroup attacks. see SEC 1 and Lopez 200 paper
# cofactor h = #E(Fq)/n , number of points on the curve?

# use user delay in future development?
# Design your own random number algorithm based on e.g. user delay on inputs.
# How many random bits do you need? How long will it take.

# comment on small numbers for private key

# sign two files with same key and same k, then calculate private key and sign third document with it
# serialise file, break into chunks of 251 bits
# hashlib has useful functions for hashing and serialising files

# mention in final paper that I initially used random module

# also look at what specifically the secrets module uses to generate randomness

# implement ECDSA
# serialise file and send it

'''
presentation is 10 minutes
about how well you communicate not how good your project is
explain whar your project is, what you've done so far and what you have left to do
don't use too much technical language
'''