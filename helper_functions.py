import numpy as np
from boxes import *

def conv_bin(arr):  # return value of binary array
    ret = 0; k=1
    for i in range(len(arr)-1, -1, -1):
        ret += k*arr[i]; k *= 2
    return int(ret)

def conv_to_bin(num, blen):
    ret = np.zeros(blen, dtype=int)
    binstr = bin(num)[2:]
    k = len(binstr)
    if blen < k:
        raise Exception("in converting to binary")
    for i in range(k-1, -1, -1):
        ret[i + blen - k] = int(binstr[i])
    return ret


def sbox_output(inp, sbox): # return sbox(inp)
    return conv_to_bin(sbox[conv_bin([inp[0], inp[5]])][conv_bin(inp[1:5])], 4)

def pbox_output(inp, inv):
    if len(inp) != 32:
        raise Exception("in pbox_output") 
    ret = np.zeros(32, dtype=int)
    for i in range(32):
        if inv:
            ret[i] = inp[PBOX_INV[i]-1]
        else:
            ret[i] = inp[PBOX[i]-1]
    return ret

def expand(inp):
    if len(inp) != 32:
        raise Exception("in expand")
    ret = np.zeros(48, dtype=int)
    for i in range(48):
        ret[i] = inp[EXP[i]-1]
    return ret

def pc1(inp):
    if len(inp) != 64:
        raise Exception("in pc1")
    ret = np.zeros(56, dtype=int)
    for i in range(56):
        ret[i] = inp[PC1[i]-1]
    return ret

def pc2(inp):
    if len(inp) != 56:
        raise Exception("in pc2")
    ret = np.zeros(48, dtype=int)
    for i in range(48):
        ret[i] = inp[PC2[i]-1]
    return ret
def left_rotate(inp, k): # rotate left by k bits
        m = len(inp)
        ret = np.zeros(m, dtype=int)
        ret[:m-k] = inp[k:]; ret[m-k:] = inp[:k]
        return ret

# key scheduling

def getkeys(inp_key, k): # generate k subkeys for k rounds using 56 bit inp_key
    if len(inp_key) != 56:
        raise Exception("in get_keys")
    # pad parity bits
    ikey = np.zeros(64, dtype=int)
    for i in range(8):
        ikey[8*i:8*i+7] = inp_key[7*i:7*i+7]
    
    # permute pc1
    ikey = pc1(ikey)
    ikey_l = ikey[:28]; ikey_r = ikey[28:]

    ret = []
    for i in range(k): # k rounds
        if i < 2: # 1 left rotation else 2
            ikey_l = left_rotate(ikey_l, 1)
            ikey_r = left_rotate(ikey_r, 1)
        else:
            ikey_l = left_rotate(ikey_l, 2)
            ikey_r = left_rotate(ikey_r, 2)
        
        subkey_i = np.append(ikey_l, ikey_r)
        ret.append(pc2(subkey_i))
    return ret

# F function of DES
def F_des(inp, ikey):
    if len(inp) != 32:
        raise Exception("in F_des")
    sinp = np.bitwise_xor(expand(inp), ikey)
    sout = np.zeros(32, dtype=int)
    for i in range(8):
        sout[4*i:4*i+4] = sbox_output(sinp[6*i:6*i+6], sboxes[i])
    return pbox_output(sout, False)

def des_round(inp_l, inp_r, subkey):
    return [np.bitwise_xor(inp_l, F_des(inp_r, subkey)), inp_r]

# DES encryption function
def des_encrypt(inp, inp_key, k): # inp assumed 64 bits (1 block), k rounds
    if len(inp) !=64:
        raise Exception("in des_round")
    keysl = getkeys(inp_key, k)
    inp_l = inp[:32]; inp_r = inp[32:]
    prev_round = des_round(inp_l, inp_r, keysl[0])
    for i in range(k-1):
        prev_round = des_round(prev_round[1], prev_round[0], keysl[i+1])
    ciphertext = np.append(prev_round[0], prev_round[1])
    return ciphertext

def conv_str(s):
   ret = np.zeros(len(s), dtype=int)
   for i in range(len(s)):
       ret[i] = int(s[i])
       
   return ret

def get_mapping(k): # map of final bit position in subkey for round k to bit position in input key
    keymap = PC2
    for i in range(48):
        if keymap[i] <= 28:
            if keymap[i] <= (30-2*k):
                keymap[i] += (2*k-2)
            else:
                keymap[i] -= (30-2*k)
        else:
            if keymap[i] <= (58-2*k):
                keymap[i] += (2*k-2)
            else:
                keymap[i] -= (30-2*k)

    keymapi = np.zeros(48, dtype=int)
    for i in range (48):
        keymapi[i] = PC1[keymap[i]-1]
    keymapf = np.zeros(48, dtype=int)
    for i in range(48):
        quo = np.ceil(keymapi[i]/8)
        keymapf[i] = keymapi[i] - quo
    return keymapf

def gen_strings(k): # 2^k
    if k==1:
        return ["0", "1"]
    tmp = gen_strings(k-1)
    ans = []
    for x in tmp:
        ans.append(x + "0"); ans.append(x + "1")
    return ans

# verify output xor guess
# allkeys = getkeys(conv_str("01101111111001000001011001111010101101100101111101011110"), 8)
# check = allkeys[0][28]^allkeys[0][24]^allkeys[2][25]^allkeys[3][3]^allkeys[4][25]^allkeys[6][25]
# print(check)
