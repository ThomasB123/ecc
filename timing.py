
import secrets
import time
import matplotlib
import matplotlib.pyplot as plt

def move(xa,ya,xb,yb):
    if xa is None:
        # 0 + point2 = point2
        return xb,yb
    if xb is None:
        # point1 + 0 = point1
        return xa,ya
    if curve.form == 0: # Short Weierstrass form
        if [xa,ya] == [xb,yb]: # doubling a point
            m = ((3*xa**2+curve.a)*inverse(curve.p,2*ya)) # (3x^2+a)/(2y)
        else: # adding two points
            m = ((yb-ya)*inverse(curve.p,xb-xa)) # (yb-ya)/(xb-xa)
        xd = (m**2 -xa-xb)
    elif curve.form == 1: # Montgomery form
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

def time221():
    times221 = []
    bits221 = []
    # M-221 (formerly Curve2213)
    rolling = []
    for i in range(0,218,step):
        privateKey = 2**i
        for j in range(step):
            start = time.time()
            publicKey = K(curve.g,privateKey)
            end = time.time()
            rolling.append(end-start)
        times221.append(sum(rolling)/len(rolling))
        bits221.append(i+1)
        rolling = []
    return bits221,times221

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

def time383():
    times383 = []
    bits383 = []
    # M-383
    rolling = []
    for i in range(0,380,step):
        privateKey = 2**i
        for j in range(step):
            start = time.time()
            publicKey = K(curve.g,privateKey)
            end = time.time()
            rolling.append(end-start)
        times383.append(sum(rolling)/len(rolling))
        bits383.append(i+1)
        rolling = []
    return bits383,times383

def time511():
    times511 = []
    bits511 = []
    # M-511 (formerly Curve511187)
    rolling = []
    for i in range(0,508,step):
        privateKey = 2**i
        for j in range(step):
            start = time.time()
            publicKey = K(curve.g,privateKey)
            end = time.time()
            rolling.append(end-start)
        times511.append(sum(rolling)/len(rolling))
        bits511.append(i+1)
        rolling = []
    return bits511,times511

class M221:
    def __init__(self):
        self.form = 1
        self.p = 2**221 - 3
        self.a = 117050
        self.b = 1
        self.g = (4,1630203008552496124843674615123983630541969261591546559209027208557)
        self.n = 2**218 + 438651314700378199859927091142747
        self.h = 2**3

class C25519:
    def __init__(self):
        self.form = 1
        self.p = 2**255 - 19
        self.a = 486662
        self.b = 1
        self.g = (9,14781619447589544791020593568409986887264606134616475288964881837755586237401)
        self.n = 2**252 + 27742317777372353535851937790883648493
        self.h = 2**3

class M383:
    def __init__(self):
        self.form = 1
        self.p = 2**383 - 187
        self.a = 2065150
        self.b = 1
        self.g = (12,4737623401891753997660546300375902576839617167257703725630389791524463565757299203154901655432096558642117242906494)
        self.n = 2**380 + 166236275931373516105219794935542153308039234455761613271
        self.h = 2**3

class M511:
    def __init__(self):
        self.form = 1
        self.p = 2**511 - 187
        self.a = 530438
        self.b = 1
        self.g = (5,2500410645565072423368981149139213252211568685173608590070979264248275228603899706950518127817176591878667784247582124505430745177116625808811349787373477)
        self.n = 2**508 + 10724754759635747624044531514068121842070756627434833028965540808827675062043
        self.h = 2**3

if __name__ == '__main__':
    for x in range(5,6):
        plt.clf()
        step = x
        curve = M221()
        bits221,times221 = time221()
        curve = C25519()
        bits25519,times25519 = time25519()
        curve = M383()
        bits383,times383 = time383()
        curve = M511()
        bits511,times511 = time511()
        plt.plot(bits221,times221,'r-',label='M-221')
        plt.plot(bits25519,times25519,'g-',label='Curve25519')
        plt.plot(bits383,times383,'b-',label='M-383')
        plt.plot(bits511,times511,'y-',label='M-511')
        plt.ylabel('Time (s)')
        plt.xlabel('Key size (bits)')
        plt.legend(loc=2)
        plt.title('Computation time vs key size for various curves'.format(step))
        plt.savefig('{}.png'.format(step))
