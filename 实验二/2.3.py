import os, random
from Crypto.Cipher import AES

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)

def encryption_oracle(plain):
    key = os.urandom(16)
    mode = random.choice([AES.MODE_ECB, AES.MODE_CBC])
    if mode == AES.MODE_ECB:
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pkcs7_pad(plain, 16)), 'ECB'
    else:
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(pkcs7_pad(plain, 16)), 'CBC'

def detect_mode(ciphertext, block_size=16):
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    return 'ECB' if len(blocks) != len(set(blocks)) else 'CBC'

# 测试
correct = 0
for _ in range(1000):
    ct, true_mode = encryption_oracle(b'A'*48)
    guessed = detect_mode(ct)
    if guessed == true_mode:
        correct += 1
print(f"准确率: {correct/10:.1f}%")