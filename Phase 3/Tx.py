#CS411-507 Cryptography Project Phase I 
# M.L. Poyraz Ozmen 23724
# Alper Bingol 23661

import random
import hashlib

import DS

def ReadPubParams(filename):
    if os.path.isfile(filename):
        f = open(filename, "r")
        q = int(f.readline())
        p = int(f.readline())
        g = int(f.readline())
        f.close()
        return q, p, g
    else:
        return -1

# 1. CheckTransaction(q; p; g) creates a random transaction and verifies its signature. For
#this, you will develop a function named \gen random tx(q, p, g)" in \Tx.py".
def gen_random_tx(q, p, g):
    
    string = "*** Bitcoin transaction ***\n"
    # Key Generation phase
    (alpha1, beta1) = DS.KeyGen(q, p, g)  # Keys of payer
    (alpha2, beta2) = DS.KeyGen(q, p, g)  # Keys of payee    

    serial = random.randint(0, 2**128 - 1)
    string += "Serial number: " + str(serial) + "\n"

    string += "Payer Public Key (beta): " + str(beta1) + "\n"
    string += 'Payee Public Key (beta): ' + str(beta2) + "\n"
    amount = random.randint(1, 1000000)
    string += "Amount: " + str(amount) + " Satoshi" + "\n"
    #assigning s and r keys
    (s, r) = DS.SignGen(string.encode('UTF-8'), q, p, g, alpha1)

    string += "Signature (s): " + str(s) + "\n"
    string += "Signature (r): " + str(r) + "\n"


    #print(string) Bitcoin transaction can be seen here

    return string


# gen_random_txblock(q, p, g, TxCnt, "transactions.txt")
def gen_random_txblock(q, p, g, TxCnt, filename):
    empty_str=''
    for i in range (TxCnt):
        string = "*** Bitcoin transaction ***\n"
        # Key Generation phase
        (alpha1, beta1) = DS.KeyGen(q, p, g)  # Keys of payer
        (alpha2, beta2) = DS.KeyGen(q, p, g)  # Keys of payee    

        serial = random.randint(0, 2**128 - 1)
        string += "Serial number: " + str(serial) + "\n"

        string += "Payer Public Key (beta): " + str(beta1) + "\n"
        string += 'Payee Public Key (beta): ' + str(beta2) + "\n"
        amount = random.randint(1, 1000000)
        string += "Amount: " + str(amount) + " Satoshi" + "\n"
        #assigning s and r keys
        (s, r) = DS.SignGen(string.encode('UTF-8'), q, p, g, alpha1)

        string += "Signature (s): " + str(s) + "\n"
        string += "Signature (r): " + str(r) + "\n"
        empty_str=empty_str + string
    #print(empty_str)
    filename='transactions.txt'
    f = open(filename,"w")
    f.write(empty_str)
    f.close()
    #print(string) Bitcoin transaction can be seen here
