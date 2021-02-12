# finds s and t such that
# sa + tb = gcd(a,b)
# uses q,r,s,t
import secrets
generator = secrets.SystemRandom()
a = 352
# = 2**252 + 27742317777372353535851937790883648493
b = 21
#b = generator.randrange(1,a-1)
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
print(i)
ans = t[i-1]%a
print('{}^-1 mod {} = {}'.format(b,a,ans))
print('should equal 1:',ans*b%a)