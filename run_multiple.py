import os

for i in range(10):
    print("Seed value: ", i)
    print("")
    os.system("python3 des_break.py " + str(i))