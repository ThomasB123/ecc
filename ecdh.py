
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
    for i in range(len(bina)-bina.index(1)):
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
print('You are using Curve25519')
p = 2**255 - 19
a,b = montgomery(486662,1)
g = (9,14781619447589544791020593568409986887264606134616475288964881837755586237401)
print('Equation of curve:  y^2 = x^3 + 486662x^2 + x   mod 2^255 - 19')
print('Starting point g =  {}'.format(g))

print()

# Change private keys here
#####################################
# private keys  2 <= ka,kb <= p-2
ka = 2**200-1 # Alice private key
kb = 2**210-1 # Bob private key
#####################################

print('Alice computes A = (ka)g mod p')
A = K(g,ka) # Alice calculation
print('A = {}\n'.format(A))

print('Alice sends A to Bob\n')

print('Bob computes B = (kb)g mod p')
B = K(g,kb) # Bob calculation
print('B = {}\n'.format(B))

print('Bob sends B to Alice\n')

# Bob sends B to Alice
print('Alice computes K = (ka)B mod p = (ka.kb)g mod p')
k = K(B,ka) # Alice calculation
print('K = {}\n'.format(k))

# Alice sends A to Bob
print('Bob computes K = (kb)A mod p = (kb.ka)g mod p')
k = K(A,kb) # Bob calculation
print('K = {}\n'.format(k))

# Alice and Bob now know the same K
print('Alice and Bob now know the same K\n')

print('x-coordinate used as secret value')
print('Secret value = {}\n'.format(k[0]))
