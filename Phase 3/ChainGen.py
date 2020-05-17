#CS411-507 Cryptography Project Phase I 
# M.L. Poyraz Ozmen 23724
# Alper Bingol 23661
from Crypto.Hash import SHA3_256
import secrets


def hTApend(Block, TxCnt,hT,transaction):
    temp_trs = transaction
    for i in range(0,TxCnt):
        temp_trs = "".join(Block[i*9:(i+1)*9]) # 9 is TxLen
        hT.append(SHA3_256.new(temp_trs.encode('UTF-8')).digest())    
    return temp_trs,hT
    
def get_rH(Block, TxCnt):
    temp_trs = ''
    hT = []

    temp_trs,hT = hTApend(Block, TxCnt,hT,temp_trs) 
    temp_TxCnt = TxCnt
    k = 0
    
    while(temp_TxCnt>1):
        for i in range(k,k+temp_TxCnt,2):
            hT.append(SHA3_256.new(hT[i]+hT[i+1]).digest())
        k = k + temp_TxCnt
        temp_TxCnt = temp_TxCnt // (2**1)
    
    root = (2*TxCnt)-2
    return hT[root]

def AddBlock2Chain(PoWLen, TxCnt, block_candidate,firstBlock): #this function used in pdf
    Block = block_candidate
    r_H = get_rH(Block, TxCnt)
    tmp_PoW = ""
    tmpPoW = ''
    tmp_nonce = 0
    
    if firstBlock != "":
        prevr_H = get_rH(firstBlock, TxCnt)
    
        Initial_Nonce_int = int(str(firstBlock[len(firstBlock) - 1])[7:-1])
        left_leftPoW = (str(firstBlock[len(firstBlock) - 2])[14:-1]).encode("UTF-8")
        initialNonce = Initial_Nonce_int.to_bytes((Initial_Nonce_int.bit_length()+7)//8, byteorder = 'big')
        tmpPoW = SHA3_256.new(prevr_H + left_leftPoW + initialNonce).hexdigest()
        
    while True:
        nonce = secrets.randbelow(2**128)
        pow_str = SHA3_256.new(r_H + tmpPoW.encode("UTF-8") + nonce.to_bytes((nonce.bit_length()+7)//8, byteorder="big")).hexdigest()

        if (pow_str[:PoWLen] == "0" * PoWLen):
            tmp_PoW = pow_str
            tmp_nonce = nonce
            break
    
    Block.append("Previous PoW: " + str(tmpPoW) + "\n")
    Block.append("Nonce: " + str(tmp_nonce) + "\n")

    strBlock = ""
    for i in range(0, len(Block)):
        tmp_block=Block[i]
        strBlock = strBlock + str(tmp_block)

    return strBlock, tmp_PoW





