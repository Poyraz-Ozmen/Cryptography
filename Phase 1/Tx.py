#CS411-507 Cryptography Project Phase I 
# M.L. Poyraz Ozmen 23724
# Alper Bingol 23661

import random
import hashlib

import DS


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