from helper_functions import *
import sys
np.random.seed(int(sys.argv[1]))

inp_key = np.random.randint(0, 2, 56) # randomly chosen 56 bit key
print("Key :", inp_key)
print(inp_key[31], inp_key[35], inp_key[52], inp_key[43], inp_key[8], inp_key[37])
N = int(2**21) # Number of known plain texts geneated
s1_cnt = np.zeros(64, dtype=int) # for guessing s1_box subkey
xor_key_guess1 = 0 # xor of rhs of first eqn

for i in range(N):
    if i%10000 == 0:
        print(i)
    P = np.random.randint(0, 2, 64) # random 64 bit plain text
    T = des_encrypt(P, inp_key, 8)
    Ph = P[:32]; Pl = P[32:]; Th = T[:32]; Tl = T[32:]
    
    # Linear approximation using 8th round
    for j in range(64):
        subkey = conv_to_bin(j, 6)
        # find F(CL)[17]
        eTR = expand(Tl)
        eTR = eTR[:6]
        out = np.bitwise_xor(eTR, subkey)
        out = sbox_output(out, s1)
        out = out[1] # 17th bit of F(CL)
        check = Ph[24]^Ph[13]^Ph[7]^Pl[19]^Pl[15]^Th[16]^Tl[24]^Tl[13]^Tl[7]^Tl[2]^out
        if check==0:
            s1_cnt[j] += 1
    
Tmax = np.max(s1_cnt); Tmin = np.min(s1_cnt)
print(Tmax, Tmin, "here")
if abs(Tmax - N/2) > abs(Tmin - N/2):
    guess = conv_to_bin(np.argmax(s1_cnt), 6)
    xor_key_guess1 = 0
else:
    guess = conv_to_bin(np.argmin(s1_cnt), 6)
    xor_key_guess1 = 1

keymap = get_mapping(8)
keyguesses = []
for i in range(6):
    keyguesses.append([keymap[i], guess[i]])

print(keyguesses)

        
