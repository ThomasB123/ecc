
# graph RSA as well, raise a number to the power of a 1-256 bit number mod n. Find some parameters
# put graph on motivation slide of presentation

import time
from Cryptodome.PublicKey import RSA

start = time.time()
keyPair = RSA.generate(bits=2048)
end = time.time()
print('Public:',hex(keyPair.e))
print('Private:',hex(keyPair.d))
print(end-start)