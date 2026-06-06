import random
from Crypto.Util.number import getPrime, inverse

def rsa_keygen(bits=1024):
    p = getPrime(bits)
    q = getPrime(bits)
    N = p * q
    phi = (p-1)*(q-1)
    e = 65537
    d = inverse(e, phi)
    return (N, e), (N, d)

def encrypt(m, pub):
    N, e = pub
    return pow(m, e, N)

def decrypt(c, priv):
    N, d = priv
    return pow(c, d, N)

# 测试
pub, priv = rsa_keygen(512)   # 512位便于测试
m = 123456789
c = encrypt(m, pub)
m2 = decrypt(c, priv)
print(f"原始: {m}, 解密: {m2}, 成功: {m == m2}")