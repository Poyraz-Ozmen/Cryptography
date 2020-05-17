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
import pyprimes

def random_prime(bitsize):
    warnings.simplefilter('ignore')
    chck = False
    while chck == False:
        p = random.randint(2**(bitsize-1), 2**bitsize-1)
        chck = pyprimes.isprime(p)
    warnings.simplefilter('default')    
    return p

def large_DL_Prime(q, bitsize):
    warnings.simplefilter('ignore')
    chck = False
    while chck == False:
        k = random.randint(2**(bitsize-1), 2**bitsize-1)
        p = k*q+1
        chck = pyprimes.isprime(p)
    warnings.simplefilter('default')    
    return p

def Param_Generator(qsize, psize):
    q = random_prime(qsize)
    p = large_DL_Prime(q, psize-qsize)
    tmp = (p-1)//q
    g = 1
    while g == 1:
        alpha = random.randrange(1, p)
        g = pow(alpha, tmp, p)
    return q, p, g


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
        #print('if')
        q = int(f.readline())
        p = int(f.readline())
        g = int(f.readline())
        f.close()
        pp = PubParam(q, p, g)
        return pp.q, pp.p, pp.g
    else:
        print('NoFile, wait it is generating file, it takes a while...')
        #pp = PubParam(2**224, 2**2048, None)
        q, p, g = Param_Generator(224,2048)
        print('initial bit length=',p.bit_length(),' if it is not 2048 bit, it will generate new p, wait please...')

        temp=p.bit_length()
        q_bit=q.bit_length()
        print('q_bit=',q_bit)
        while (temp!=2048 or q_bit!=224):
            q, p, g = Param_Generator(224,2048)
            temp=p.bit_length()
            q_bit = q.bit_length()
            print('new bit_length is',temp,' if it is not 2048 bit, it will generate new p, wait please...', '   ', 'q_bit=',q_bit)
        #   print('else2')
        f = open("pubparams.txt","w")
        f.write(str(q)+"\n")
        f.write(str(p)+"\n")
        f.write(str(g))
        f.close()
        return q,p,g
    #print ('pp.q: ',pp.q,'len=',
    #print ('pp.p: ',pp.p)
    #print ('pp.g: ',pp.g)




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
