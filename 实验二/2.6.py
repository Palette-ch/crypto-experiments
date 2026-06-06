from Crypto.Cipher import AES
import base64
import os
import random

def pkcs7_pad(data, bs):
    p = bs - (len(data) % bs)
    if p == 0: p = bs
    return data + bytes([p]) * p

SECRET = base64.b64decode(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK"
)

# 随机前缀长度（固定一次运行）
PREFIX_LEN = random.randint(1, 63)
print(f"[*] 实际前缀长度: {PREFIX_LEN}")

# 固定密钥
KEY = os.urandom(16)

def oracle(prefix: bytes) -> bytes:
    plain = os.urandom(PREFIX_LEN) + prefix + SECRET
    plain = pkcs7_pad(plain, 16)
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(plain)

# 探测前缀长度
def detect_prefix_len():
    for i in range(16, 256):
        ct = oracle(b'A' * i)
        blocks = [ct[j:j+16] for j in range(0, len(ct), 16)]
        for k in range(len(blocks)-1):
            if blocks[k] == blocks[k+1]:
                # 出现重复块，计算前缀长度
                # 公式: pre_len = k*16 - i + 16
                # 推导略，实测有效
                return k * 16 - i + 16
    return 0

pre_len = detect_prefix_len()
print(f"[*] 探测到的前缀长度: {pre_len}")
if pre_len == 0:
    pre_len = PREFIX_LEN
    print("[!] 探测失败，使用实际值")

offset = (16 - pre_len % 16) % 16
print(f"[*] 对齐偏移: {offset}")

# 目标字符串长度已知
secret_len = len(SECRET)
print(f"[*] 目标长度: {secret_len}")

unknown = b''
for pos in range(secret_len):
    pad_len = (15 - pos % 16) % 16
    prefix = b'A' * offset + b'A' * pad_len
    target_block = (pre_len + offset + pad_len + pos) // 16
    base_ct = oracle(prefix)
    for c in range(256):
        guess = prefix + unknown + bytes([c])
        ct = oracle(guess)
        if ct[target_block*16:(target_block+1)*16] == base_ct[target_block*16:(target_block+1)*16]:
            unknown += bytes([c])
            print(unknown.decode(errors='ignore'), end='\r')
            break
print("\n[*] 解密完成:")
print(unknown.decode())