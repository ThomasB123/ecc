
import time
import matplotlib.pyplot as plt

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

# old method:

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

def moveOld(xa,ya,xb,yb):
    if [xa,ya] == [xb,yb]:
        # doubling a point
        m = ((3*xa**2+curve.a)*inverse(curve.p,2*ya)) # (3x^2+a)/(2y)
    else:
        # adding two points
        m = ((yb-ya)*inverse(curve.p,xb-xa)) # (yb-ya)/(xb-xa)
    xd = (m**2 -xa-xb)
    yd = (m*(xa-xd) - ya)
    return xd%curve.p,-yd%curve.p

def KOld(start,k):
    points = [start]
    bina = binary(k)
    for i in range(len(bina)):#-bina.index(1)):
        points.append(moveOld(points[-1][0],points[-1][1],points[-1][0],points[-1][1])) # double
    index = bina.index(1) # find first occurence of 1 in the binary representation
    out = points[index] # start with smallest multiple of g
    for i in range(index+1,len(bina)): # count up from the smallest multiple
        if bina[i] == 1:
            out = moveOld(out[0],out[1],points[i][0],points[i][1])
    return out


# new method

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
#https://cr.yp.to/ecdh/curve25519-20060209.pdf
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



def timeOld25519():  
    timesOld25519 = []
    bitsOld25519 = []
    # Curve25519
    rolling = []
    for i in range(0,252,step):
        privateKey = 2**i
        for j in range(step):
            start = time.time()
            publicKey = KOld(curve.g,privateKey)
            end = time.time()
            rolling.append(end-start)
        timesOld25519.append(sum(rolling)/len(rolling))
        bitsOld25519.append(i+1)
        rolling = []
    return bitsOld25519,timesOld25519

def time25519():  
    times25519 = []
    bits25519 = []
    # Curve25519
    rolling = []
    for i in range(0,252,step):
        privateKey = 2**i
        for j in range(step):
            start = time.time()
            publicKey = K(curve.g,privateKey)
            end = time.time()
            rolling.append(end-start)
        times25519.append(sum(rolling)/len(rolling))
        bits25519.append(i+1)
        rolling = []
    return bits25519,times25519

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
    for x in range(5,6):
        plt.clf()
        step = x
        #curve = M221()
        #bits221,times221 = time221()
        curve = C25519()
        bits25519,times25519 = time25519()
        curve = C25519()
        bitsOld25519,timesOld25519 = timeOld25519()
        #curve = M383()
        #bits383,times383 = time383()
        #curve = M511()
        #bits511,times511 = time511()
        #plt.plot(bits221,times221,'r-',label='M-221')
        plt.plot(bits25519,times25519,'r-',label='Curve25519')
        plt.plot(bitsOld25519,timesOld25519,'g-',label='Old Curve25519')
        #plt.plot(bits383,times383,'b-',label='M-383')
        #plt.plot(bits511,times511,'y-',label='M-511')
        plt.ylabel('Time (s)')
        plt.xlabel('Key size (bits)')
        plt.legend(loc=2)
        plt.title('Computation time vs key size for various multiplication methods'.format(step))
        plt.savefig('{}.png'.format(step))
