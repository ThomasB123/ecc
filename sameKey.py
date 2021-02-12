
# computing m and k using 2 signature pairs (R,S) that use same m

import hashlib
import secrets

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

def K(start,k): # calculate k*start
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

def sendSignature(): # ECDSA algorithm
    message1 = b'Hello!'
    message2 = b'Goodbye!'
    message_hash1 = hashlib.sha512(message1)
    message_hash2 = hashlib.sha512(message2)
    integer1 = int.from_bytes(message_hash1.digest(),'big')
    integer2 = int.from_bytes(message_hash2.digest(),'big')
    e1 = integer1 >> (integer1.bit_length() - n.bit_length())
    e2 = integer2 >> (integer2.bit_length() - n.bit_length())

    k = 4
    r = K(g,k)[0] % n
    s1 = inverse(n,k)*(e1+privateKey*r) % n
    s2 = inverse(n,k)*(e2+privateKey*r) % n
    print('First Signature: 0x{:x}\n 0x{:x}'.format(r,s1))
    print('Second Signature: 0x{:x}\n 0x{:x}'.format(r,s2))
    print()
    return r,s1,s2

def breakSignature(r,s1,s2):
    message1 = b'Hello!'
    message2 = b'Goodbye!'
    message_hash1 = hashlib.sha512(message1)
    message_hash2 = hashlib.sha512(message2)
    integer1 = int.from_bytes(message_hash1.digest(),'big')
    integer2 = int.from_bytes(message_hash2.digest(),'big')
    e1 = integer1 >> (integer1.bit_length() - n.bit_length())
    e2 = integer2 >> (integer2.bit_length() - n.bit_length())

    # method 1:
    pKey = (s2*e1-s1*e2)*inverse(n,r*(s1-s2)) % n
    k = (e1+pKey*r)*inverse(n,s1) % n
    # method 2:
    k = (e1-e2)*inverse(n,s1-s2) % n
    pKey = (k*s1-e1)*inverse(n,r) % n
    
    if pKey == privateKey:
        print('Calculated private key! 0x{:x}'.format(pKey))
    print('Random variable k =',k)


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

generator = secrets.SystemRandom()
privateKey = generator.randrange(n//2,n-1) # {1,...,n-1} where n is the order of the subgroup
publicKey = K(g,privateKey)


r,s1,s2 = sendSignature()
breakSignature(r,s1,s2)