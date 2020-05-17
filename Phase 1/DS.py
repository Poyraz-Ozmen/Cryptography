#CS411-507 Cryptography Project Phase I 
# M.L. Poyraz Ozmen 23724
# Alper Bingol 23661

from Crypto.Util import number
import math
import os
import random
import string
import warnings
from Crypto.Hash import SHA3_256


def random_string(size=6, chars=string.ascii_uppercase + string.ascii_lowercase+ string.digits):
    return ''.join(random.choice(chars) for x in range(size))


def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y


def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m

class PubParam:
    def __init__(self, qq, pp, gg):
        # if a g value is given that means we have the values
        if gg is not None:
            self.p = pp
            self.q = qq
            self.g = gg
        # if g is not given we have to create our own values
        else:
            np = number.size(pp)
            nq = number.size(qq)
            # given p and q size\ generate q
            self.q = number.getPrime(nq)
            # random number resulting from 2**np
            T = number.getRandomNBitInteger(np-nq)
            # checking T*Q + 1 is not prime
            while True:
                #previous operation for random number 
                T = number.getRandomNBitInteger(np-nq)
                # generate the P
                self.p = self.q * T + 1
                if number.isPrime(self.p) and number.size(self.p) == np:
                    break



            self.g = 1
            # while g is not 1 stop
            while self.g == 1:
                h = number.getRandomRange(2, self.p-1)
                self.g = pow(h, (self.p-1)//self.q, self.p)

# read from the pubparams.txt file if exists otherwise create one and use those
def GenerateOrRead(file):
    if os.path.isfile(file):
        f = open("pubparams.txt", "r")
        q = int(f.readline())
        p = int(f.readline())
        g = int(f.readline())
        f.close()
        pp = PubParam(q, p, g)
    else:
        pp = PubParam(2**224, 2**2048, None)
        f = open("pubparams.txt","w")
        f.write(str(pp.q)+"\n")
        f.write(str(pp.p)+"\n")
        f.write(str(pp.g))
        f.close()
    return pp.q, pp.p, pp.g




#generate the Keys from Q P G with provided formlas
def KeyGen(Q, P, G):
    alpha = number.getRandomRange(1, Q-1)
    beta = pow(G, alpha, P)
    return alpha, beta

#(s, r) = DSS.SignGen(message, q, p, g, alpha)
# Sign the message
def SignGen(m, Q, P, G, alpha):
    k = number.getRandomRange(1, Q-1)
    # decode the m's utf-8 encoding
    m = m.decode('utf-8')
    hsh = SHA3_256.new()
    r = pow(G, k, P) % Q
    temp = str(m) 
    hsh.update(bytes(temp, 'utf-8'))
    h = int(hsh.hexdigest(), 16) % Q
    s = (alpha*r - k*h) % Q 
    return s,r

#return DSS.SignVer(message, s, r, q, p, g, beta)
#check the signature
def SignVer(m, s, r, q, p, g, beta):
    m = m.decode('utf-8')
    #print('after decode:',m) For debugging
    #print("======after decode========")
    #print('s:',s)
    #print('r:',r)
    #print('q:',q)
    #print('p:',p)
    #print('g:',g)
    #print('beta:',beta)
    hsh = SHA3_256.new()
    hsh.update(bytes((str(m)).encode('utf-8')))
    h = int(hsh.hexdigest(), 16) % q
    
    v =  modinv(h, q)
    z1 = (s*v) % q
    z2 = (r*v) % q
    beta_temp = pow(beta, z2, p)
    g_temp = modinv(g, p)
    g_temp2= pow(g_temp, z1, p)
    u = ((beta_temp * g_temp2) % p ) % q
    #print('u:',u)
    #print('r:',r)

    if (u==r):
        return 0
    else:
        return -1
