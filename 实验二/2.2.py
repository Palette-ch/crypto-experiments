from Crypto.Cipher import AES
from base64 import b64decode

def aes_ecb_decrypt(block, key):
    return AES.new(key, AES.MODE_ECB).decrypt(block)

def cbc_decrypt(ciphertext, key, iv):
    block_size = 16
    prev = iv
    plain = b''
    for i in range(0, len(ciphertext), block_size):
        cur_block = ciphertext[i:i+block_size]
        dec = aes_ecb_decrypt(cur_block, key)
        plain_block = bytes(a ^ b for a,b in zip(dec, prev))
        plain += plain_block
        prev = cur_block
    # 去除 PKCS#7 填充
    pad_len = plain[-1]
    return plain[:-pad_len]

with open('./实验二/10.txt') as f:
    cipher_b64 = f.read()
ciphertext = b64decode(cipher_b64)
key = b'YELLOW SUBMARINE'
iv = b'\x00' * 16
plain = cbc_decrypt(ciphertext, key, iv)
print(plain.decode())