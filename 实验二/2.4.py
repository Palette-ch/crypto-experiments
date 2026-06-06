from Crypto.Cipher import AES
import base64
import os

def pkcs7_pad(data, bs):
    p = bs - (len(data) % bs)
    if p == 0: p = bs
    return data + bytes([p]) * p

# 固定的目标字符串
SECRET = base64.b64decode(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK"
)

# 固定密钥（在一次攻击中保持不变）
KEY = os.urandom(16)

def oracle(prefix: bytes) -> bytes:
    plain = prefix + SECRET
    plain = pkcs7_pad(plain, 16)
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(plain)

# 1. 获取 SECRET 长度
base_len = len(oracle(b''))
secret_len = base_len
for i in range(1, 17):
    if len(oracle(b'A' * i)) != base_len:
        secret_len = base_len - i
        break
print(f"[*] 目标字符串长度: {secret_len}")

# 2. 逐字节爆破
unknown = b''
for pos in range(secret_len):
    pad_len = (15 - pos % 16) % 16
    prefix = b'A' * pad_len
    target_block = (pad_len + pos) // 16
    base_ct = oracle(prefix)
    for c in range(256):
        guess = prefix + unknown + bytes([c])
        ct = oracle(guess)
        if ct[target_block*16:(target_block+1)*16] == base_ct[target_block*16:(target_block+1)*16]:
            unknown += bytes([c])
            # 实时打印进度
            print(unknown.decode(errors='ignore'), end='\r')
            break
print("\n[*] 解密完成:")
print(unknown.decode())