from helper_functions import *
from copy import deepcopy
import sys

np.random.seed(int(sys.argv[1]))

char_1 = "0100000000001000000000000000000000000100000000000000000000000000" # 40 08 00 00 04 00 00 00 characteristic
char_2 = "0000000000100000000000000000100000000000000000000000010000000000" # 00 20 00 08 00 00 04 00 characteristic

char_1 = conv_str(char_1); char_2 = conv_str(char_2)
inp_key = np.random.randint(0, 2, 56) # randomly chosen 56 bit key
print("Key :", inp_key)

N = 250 # num input pairs initial estimate
inp_pairs1 = [] # list of pairs of plaintext messages for characteristic 1
inp_pairs2 = [] # for characteristic 2

for i in range(N):
    msg = np.random.randint(0, 2, 64) # random 64 bit message
    inp_pairs1.append([msg, np.bitwise_xor(msg, char_1)])
    inp_pairs2.append([msg, np.bitwise_xor(msg, char_2)])

# characteristic 1 analysis
# s2, s5, s6, s7, s8 have output xor 0 after round 4. Satisfy F' = c' xor TL'
slist = [2, 5, 6, 7, 8]
slistb = [s2, s5, s6, s7, s8]
c_xor = "00000100000000000000000000000000" # c' value (04 00 00 00)
c_xor = conv_str(c_xor)

counts = np.zeros([5, 64], dtype=int) # for each of the above s, for each of 64 possibe subkey values of round 6

for msg_pair in inp_pairs1:
    [T1, T2] = [des_encrypt(msg_pair[0], inp_key, 6), des_encrypt(msg_pair[1], inp_key, 6)] # get ciphertexts
    f1 = T1[32:] # f' value for msg 1: input to F_des in 6th round
    f2 = T2[32:]
    F_xor = np.bitwise_xor(c_xor, np.bitwise_xor(T1[:32], T2[:32])) # F' value
    F_xorinv = pbox_output(F_xor, True)
    ef1 = expand(f1); ef2 = expand(f2)
    for i in range(5): # iterate over sboxes
        for j in range(64):
            subkey = conv_to_bin(j, 6)
            # calculate output xor
            out1 = np.bitwise_xor(ef1[(slist[i]-1)*6:slist[i]*6], subkey)
            out1 = sbox_output(out1, slistb[i])
            out2 = np.bitwise_xor(ef2[(slist[i]-1)*6:slist[i]*6], subkey)
            out2 = sbox_output(out2, slistb[i])
            
            out_xor = np.bitwise_xor(out1, out2)
            tmpv = F_xorinv[(slist[i]-1)*4:slist[i]*4]
            if (out_xor == tmpv).all():
                counts[i][j] += 1

keyguess1 = [] # for s2, s5, s6, s7, s8
for i in range(5):
    keyguess1.append(conv_to_bin(np.argmax(counts[i]), 6))

# characteristic 2 analysis
# s1, s2, s4, s5, s6 have output xor 0 after round 4. Satisfy F' = c' xor TL'
slist = [1, 2, 4, 5, 6]
slistb = [s1, s2, s4, s5, s6]
c_xor = "00000000000000000000010000000000" # c' value (00 00 04 00)
c_xor = conv_str(c_xor)

counts = np.zeros([5, 64], dtype=int) # for each of the above s, for each of 64 possibe subkey values of round 6

for msg_pair in inp_pairs2:
    [T1, T2] = [des_encrypt(msg_pair[0], inp_key, 6), des_encrypt(msg_pair[1], inp_key, 6)] # get ciphertexts
    f1 = T1[32:] # f' value for msg 1: input to F_des in 6th round
    f2 = T2[32:]
    F_xor = np.bitwise_xor(c_xor, np.bitwise_xor(T1[:32], T2[:32])) # F' value
    F_xorinv = pbox_output(F_xor, True)
    ef1 = expand(f1); ef2 = expand(f2)
    for i in range(5): # iterate over sboxes
        for j in range(64):
            subkey = conv_to_bin(j, 6)
            # calculate output xor
            out1 = np.bitwise_xor(ef1[(slist[i]-1)*6:slist[i]*6], subkey)
            out1 = sbox_output(out1, slistb[i])
            out2 = np.bitwise_xor(ef2[(slist[i]-1)*6:slist[i]*6], subkey)
            out2 = sbox_output(out2, slistb[i])
            
            out_xor = np.bitwise_xor(out1, out2)
            tmpv = F_xorinv[(slist[i]-1)*4:slist[i]*4]
            if (out_xor == tmpv).all():
                counts[i][j] += 1

keyguess2 = [] # for s1, s2, s4, s5, s6
for i in range(5):
    keyguess2.append(conv_to_bin(np.argmax(counts[i]), 6))

if not ((keyguess1[0]==keyguess2[1]).all() and (keyguess1[1]==keyguess2[3]).all() and (keyguess1[2]==keyguess2[4]).all()):
    print("Output from characteristics do not match")
    exit(0)

keyguess = np.concatenate((keyguess2[0], keyguess2[1], np.zeros(6, dtype=int), keyguess2[2], keyguess2[3],keyguess2[4], keyguess1[3], keyguess1[4]))

keymap = get_mapping(6)
final_guess = np.zeros(56, dtype=int)
pos_guessed = np.zeros(56, dtype=bool) # 1 if alreaady guessed
for i in range(48):
    if not (i >= 12 and i < 18): # not s3
        final_guess[keymap[i]] = keyguess[i]
        pos_guessed[keymap[i]] = True

pos_to_guess = []
for i in range(56):
    if not pos_guessed[i]:
        pos_to_guess.append(i)

# brute force over remaining 14 bits
values = gen_strings(14)
for value in values:
    guess = deepcopy(final_guess)
    for i in range(14):
        guess[pos_to_guess[i]]= int(value[i])
    
    # check if guess is correct by matching encryption
    T1 = des_encrypt(inp_pairs1[0][0], inp_key, 6) 
    T2 = des_encrypt(inp_pairs1[0][0], guess, 6)
    if (T1 == T2).all():
        print("Guessed key:", guess)
        break

if (guess == inp_key).all():
    print("-------------Matches-------------")