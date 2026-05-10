import base64
from itertools import combinations

def hamming(a,b):
    return sum(bin(x^y).count('1') for x,y in zip(a,b))

def score(b):
    return sum(1 for x in b if x in b'etaoinshrdlcumwfgypbvkjxqz ')

def get_key(s):
    d = bytes.fromhex(s)
    return max(range(256), key=lambda k: score(bytes(x^k for x in d)))

with open("6.txt","r") as f:
    data = base64.b64decode(f.read())

dists = []
for ks in range(2,41):
    chunks = [data[i*ks:(i+1)*ks] for i in range(4)]
    avg = sum(hamming(c1,c2) for c1,c2 in combinations(chunks,2))/(ks*6)
    dists.append((avg,ks))
best_ks = sorted(dists)[0][1]

blocks = [data[i::best_ks] for i in range(best_ks)]
key = bytes(get_key(b.hex()) for b in blocks)
plain = bytes(data[i]^key[i%len(key)] for i in range(len(data))).decode()

print(f"密钥：{key.decode()}\n明文：{plain}")