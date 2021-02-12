
# plotting scatter plots of:
# number of 1 bits in key vs multiplication time
# log key value vs multiplication time
# see if there is any correlation


import time
import matplotlib.pyplot as plt
import secrets
import math

# investigating timing differences and security benefits of different multiplication methods

# used by both old and new methods

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

def move(xa,ya,xb,yb):
    if xa is None:
        # 0 + point2 = point2
        return xb,yb
    if xb is None:
        # point1 + 0 = point1
        return xa,ya
    if curve.form == 0: # Short Weierstrass
        if [xa,ya] == [xb,yb]: # doubling a point
            m = ((3*xa**2+curve.a)*inverse(curve.p,2*ya)) # (3x^2+a)/(2y)
        else: # adding two points
            m = ((yb-ya)*inverse(curve.p,xb-xa)) # (yb-ya)/(xb-xa)
        xd = (m**2 -xa-xb)
    elif curve.form == 1: # Montgomery
        if [xa,ya] == [xb,yb]: # doubling a point
            m = (3*xa**2+2*curve.a*xa+1)*inverse(curve.p,2*curve.b*ya) # (3x^2+2ax+1)/(2by)
        else: # adding two points
            m = (yb-ya)*inverse(curve.p,xb-xa) # (yb-ya)/(xb-xa)
        xd = curve.b*m**2 -curve.a-xa-xb
    yd = m*(xa-xd) - ya # flipped in x axis here
    return xd%curve.p,yd%curve.p

def K(start,k): # calculate k*start
    # k is integer and start is point
    result = (None,None)
    addend = start
    ones = 0
    while k:
        if k & 1:
            result = move(result[0],result[1],addend[0],addend[1]) # add
            ones += 1
        addend = move(addend[0],addend[1],addend[0],addend[1]) # double
        k >>= 1
    return result,ones

def time25519():  
    times25519 = []
    ones25519 = []
    # Curve25519
    rolling = []
    generator = secrets.SystemRandom()
    for i in range(300):
        privateKey = generator.randrange(2,curve.n-1)
        for j in range(3):
            start = time.time()
            publicKey,ones = K(curve.g,privateKey)
            end = time.time()
            #rolling.append(end-start)
            rolling.append(end-start)
        times25519.append(sorted(rolling)[1])
        ones25519.append(ones)
        #ones25519.append(ones)
        #ones25519.append(math.log(privateKey,2))
        rolling = []
    return ones25519,times25519

class C25519:
    def __init__(self):
        self.form = 1
        self.p = 2**255 - 19
        self.a = 486662
        self.b = 1
        self.g = (9,14781619447589544791020593568409986887264606134616475288964881837755586237401)
        self.n = 2**252 + 27742317777372353535851937790883648493
        self.h = 2**3

if __name__ == '__main__':
    plt.clf()
    curve = C25519()
    ones25519,times25519 = time25519()
    plt.plot(ones25519,times25519,'ro',label='Curve25519')
    plt.ylabel('Time (s)')
    plt.xlabel('Number of 1s in binary expansion of key')
    plt.title('Computation time vs number of 1s bits in key')
    plt.savefig('ones300SmoothedAny.png')
