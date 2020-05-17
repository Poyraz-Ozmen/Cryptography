#CS411-507 Cryptography Project Phase II
# M.L. Poyraz Ozmen 23724
# Alper Bingol 23661

import os.path
import pyprimes
from Crypto.Util import number
import math 
import hashlib
import random

# fills transactions in array
def fill_trs_array(trs_arr,rows,TxCnt):
    cnt_temp = 0
    for i in range(0, len(rows) - 1, 7): 
        trs_arr[cnt_temp] = rows[i] + rows[i + 1] + rows[i + 2] + rows[i + 3] + rows[i + 4] + rows[i + 5] + rows[i + 6] #appends every 7 rows which is a one transaction
        cnt_temp += 1
    return trs_arr

#Nonce    
def nonce_check(H_r,PoWLen,nonce):
    for nonce in range(0, 2**32):
        if(hashlib.sha3_256(H_r + (str(nonce) + "\n").encode("UTF-8")).hexdigest()[:PoWLen] == PoWLen * "0"):
            break    
    return nonce


#computes Proof of Work for block 
#generating a PoW for the block in transactions.txt   
def PoW(PoWLen, q, p, g, TxCnt, filename): #PowLen is at least 5
    file = open(filename, "r")
    rows = file.readlines() #
    trs_arr = [None] * TxCnt # transactions array
    file.close()
    
    fill_trs_array(trs_arr,rows,TxCnt)
    initial_list = []

    for i in range(0, len(trs_arr)):
        initial_list.append(hashlib.sha3_256((trs_arr[i].encode("UTF-8"))).digest()) 

    while len(initial_list) != 1:
        final_list = []
        for k in range(0, len(initial_list), 2):
            final_list.append(hashlib.sha3_256(initial_list[k] + initial_list[k + 1]).digest())
        initial_list = final_list

    
    H_r = initial_list[0]
    nonce = 0 #initialize nonce
    nonce = nonce_check(H_r,PoWLen,nonce) # check nonce 
            
    rows.append("Nonce: " + str(nonce))  #appends nonce at the end of the block
    
    temp_str = ""  
    for k in rows:  
        temp_str += k
    return temp_str

#checking Pow for block.txt file or block_sample.txt
def CheckPow(p, q, g, PoWLen, TxCnt, filename):
    file = open(filename, 'r')
    rows = file.read().splitlines()
    file.close()
    nonce = rows[-1][7:]
    
    file = open(filename, "r")
    rows = file.readlines()
    trs_arr = [None] * TxCnt
    file.close()
    
    fill_trs_array(trs_arr,rows,TxCnt)
    initial_list = []

    for i in range(0, len(trs_arr)):
        initial_list.append(hashlib.sha3_256(trs_arr[i].encode("UTF-8")).digest()) 

    while len(initial_list) != 1:
        final_list = []
        for k in range(0, len(initial_list), 2):
            final_list.append(hashlib.sha3_256(initial_list[k] + initial_list[k + 1]).digest())
        initial_list = final_list
    
    H_r = initial_list[0]

    return str(hashlib.sha3_256(H_r + str(nonce + "\n").encode("UTF-8")).hexdigest())












