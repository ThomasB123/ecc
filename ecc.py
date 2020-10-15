
# Elliptic Curve Cryptography is the modern standard for efficient key exchange

# This project will involve implementing and testing an Elliptic Curve Cryptosystem.

# At an advanced level the project could compare the efficiency of ECC with RSA crptography.

# Explore generation of curves and suitable initial points.

# Explore attacks on ECC and compare with the security of RSA at similar key sizes.

# Implement and test calculations secure against timing attacks (e.g. Montgomery multiplication)


# Anticipated outcomes:
# A working elliptic curve crypto system
# Empirical testing of the system

# cipolla's algorithm
# euclid's extended algorithm is *pow() thing

# (y,p) are coprime, gives you an a,b such that ay+bp = 1 . ay = 1 mod p. a is 'mod p inverse of y'
# use 2y instead , multiply by a gives same as dividing by 2y in mod p
# ak2y = k(a2y) = k mod p

# explore efficiency of computing only neccessary doublings of g vs computing all doublings
# would first way make it vulnerable to timing attacks

# for literature review, have section on attacks, such as timing

def binary(num):
    x = 1000 # max index of number input, i.e. 2^x
    out = []
    for i in range(x+1):
      if num >= 2**x:
        out.insert(0,1)
        num -= 2**x
      else:
        out.insert(0,0)
      x -= 1
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
    for i in range(len(bina)-bina.index(1)-1):
        points.append(move(points[-1][0],points[-1][1],points[-1][0],points[-1][1])) # double
    index = bina.index(1)
    out = points[index] # start with largest multiple of g
    for i in range(index+1,len(bina)-1): # count down from the largest multiple
        if bina[i] == 1:
            out = move(out[0],out[1],points[i][0],points[i][1])
    return out

# several different ways to express elliptic curves

# short weierstrass equation:
# y^2 = x^3 + ax + b where 4a^3 + 27b^2 != 0

# montgomery equation:
# by^2 = x^3 + ax^2 + x where b(a^2 - 4) != 0
# sub x = bu - a/3 and y = bv to produce weierstrass v^2 = u^3 + au + b where a = (3 - a^2)/(3b^2) and b = (2a^3 - 9a)/(27b^3)

# edwards equation:
# x^2 + y^2 = 1 + dx^2y^2 where d(1 - d) != 0
# sub x = u/v and y = (u - 1)/(u + 1) to produce montgomery bv^2 = u^3 + au^2 + u where a = 2(1 + d)/(1 - d) and b = 4/(1 - d)

def montgomery(a,b): # convert from montgomery to short weierstrass
    # a = (3 - a^2)/(3b^2) and b = (2a^3 - 9a)/(27b^3)
    return (3-a**2)*pow(3*b**2,p-2,p),(2*a**3-9*a)*pow(27*b**3,p-2,p)

def edwards(d): # convert from edwards to short weierstrass
    # a = 2(1 + d)/(1 - d) and b = 4/(1 - d)
    return montgomery(2*(1+d)*pow(1-d,p-2,p),4*pow(1-d,p-2,p))

# public parameters: p,a,b,g
choice = input('''
Which curve would you like to use?

    1. M-221
    2. E-222
    3. Curve1174
    4. Curve25519
    5. E-382
    6. M-383
    7. Curve41417
    8. Ed448-Goldilocks
    9. M-511
    10. E-521

Your Choice > ''')

print()

if choice == '1':
    # M-221 (formerly Curve2213)
    print('You are using M-221')
    p = 2**221 - 3
    a,b = montgomery(117050,1)
    g = (4,1630203008552496124843674615123983630541969261591546559209027208557)
    print('Equation of curve:  y^2 = x^3 + 117050x^2 + x   mod 2^221 - 3')
    print('Starting point g =  {}'.format(g))
elif choice == '2':
    # E-222
    print('You are using E-222')
    p = 2**222 - 117
    a,b = edwards(160102)
    g = (2705691079882681090389589001251962954446177367541711474502428610129,28)
    print('Equation of curve:  x^2 + y^2 = 1 + 160102x^2y^2   mod 2^222 - 117')
    print('Starting point g =  {}'.format(g))
elif choice == '3':
    # Curve1174
    print('You are using Curve1174')
    p = 2**251 - 9
    a,b = edwards(-1174)
    g = (1582619097725911541954547006453739763381091388846394833492296309729998839514,3037538013604154504764115728651437646519513534305223422754827055689195992590)
    print('Equation of curve:  x^2 + y^2 = 1 - 1174x^2y^2   mod 2^251 - 9')
    print('Starting point g =  {}'.format(g))
elif choice == '4':
    # Curve25519
    print('You are using Curve25519')
    p = 2**255 - 19
    a,b = montgomery(486662,1)
    g = (9,14781619447589544791020593568409986887264606134616475288964881837755586237401)
    print('Equation of curve:  y^2 = x^3 + 486662x^2 + x   mod 2^255 - 19')
    print('Starting point g =  {}'.format(g))
elif choice == '5':
    # E-382
    print('You are using E-382')
    p = 2**382 - 105
    a,b = edwards(-67254)
    g = (3914921414754292646847594472454013487047137431784830634731377862923477302047857640522480241298429278603678181725699,17)
    print('Equation of curve:  x^2 + y^2 = 1 - 67254x^2y^2   mod 2^382 - 105')
    print('Starting point g =  {}'.format(g))
elif choice == '6':
    # M-383
    print('You are using M-383')
    p = 2**383 - 187
    a,b = montgomery(2065150,1)
    g = (12,4737623401891753997660546300375902576839617167257703725630389791524463565757299203154901655432096558642117242906494)
    print('Equation of curve:  y^2 = x^3 + 2065150x^2 + x   mod 2^383 - 187')
    print('Starting point g =  {}'.format(g))
elif choice == '7':
    # Curve41417 (formerly Curve3617)
    print('You are using Curve41417')
    p = 2**414 - 17
    a,b = edwards(3617)
    g = (17319886477121189177719202498822615443556957307604340815256226171904769976866975908866528699294134494857887698432266169206165,34)
    print('Equation of curve:  x^2 + y^2 = 1 + 3617x^2y^2   mod 2^414 - 17')
    print('Starting point g =  {}'.format(g))
elif choice == '8':
    # Ed448-Goldilocks
    print('You are using Ed448-Goldilocks')
    p = 2**448 - 2**224 - 1
    a,b = edwards(-39081)
    g = (117812161263436946737282484343310064665180535357016373416879082147939404277809514858788439644911793978499419995990477371552926308078495,19)
    print('Equation of curve:  x^2 + y^2 = 1 - 39081x^2y^2   mod 2^448 - 2^224 - 1')
    print('Starting point g =  {}'.format(g))
elif choice == '9':
    # M-511 (formerly Curve511187)
    print('You are using M-511')
    p = 2**511 - 187
    a,b = montgomery(530438,1)
    g = (5,2500410645565072423368981149139213252211568685173608590070979264248275228603899706950518127817176591878667784247582124505430745177116625808811349787373477)
    print('Equation of curve:  y^2 = x^3 + 530438x^2 + x   mod 2^511 - 187')
    print('Starting point g =  {}'.format(g))
elif choice == '10':
    # E-521
    print('You are using E-521')
    p = 2**521 - 1
    a,b = edwards(-376014)
    g = (1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324,12)
    print('Equation of curve:  x^2 + y^2 = 1 - 376014x^2y^2  mod 2^521 - 1')
    print('Starting point g =  {}'.format(g))
else:
    # example
    print('You are using a small example')
    p = 263
    a,b = 2,3 
    g = (200,39)
    print('Equation of curve:  y^2 = x^3 + 2x + 3   mod 263')
    print('Starting point g =  {}'.format(g))

print()

# Change private keys here
#####################################
# private keys  2 <= ka,kb <= p-2
ka = 2**500-1 # Alice private key
kb = 2**510-1 # Bob private key
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

# flipping point in x axis ?

# investigate calculating all powers of 2 then only adding neccessary ones to make ka/kb rather than only calculating up to neccessary
# is it much slower? should make timing attack more difficult
