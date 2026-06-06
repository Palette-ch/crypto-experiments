from Crypto.Cipher import AES
import os

def pkcs7_pad(data, bs):
    p = bs - (len(data) % bs)
    if p == 0: p = bs
    return data + bytes([p]) * p

def pkcs7_unpad(data):
    return data[:-data[-1]]

KEY = os.urandom(16)
IV = os.urandom(16)

def encrypt(userdata):
    prefix = b"comment1=cooking MCs;userdata="
    plain = prefix + userdata + b";comment2= like a pound of bacon"
    plain = pkcs7_pad(plain, 16)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return IV + cipher.encrypt(plain)

def decrypt(ct):
    iv = ct[:16]
    body = ct[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    plain = cipher.decrypt(body)
    return pkcs7_unpad(plain)

# 构造payload，使得";admin=true"正好位于独立块内，并且前面填充足够的A使目标块对齐
# 计算前缀长度（包括固定前缀和userdata=）: len(prefix) = 30
# 我们需要让目标字符串从块边界开始。块大小16，当前前缀长度30，还需要填充2个字节使30+2=32，即块2开始
payload = b"A" * 2 + b";admin=true"
ct_full = encrypt(payload)
original = decrypt(ct_full)
print("原始:", original)

# 找到目标子串的位置
target = b";admin=true"
pos = original.find(target)
print("位置:", pos)

# 目标所在块索引
block_idx = pos // 16
offset = pos % 16

# 修改前一个密文块（或IV）
ciphertext = bytearray(ct_full)
if block_idx == 0:
    target_block = ciphertext[:16]  # IV
else:
    # 前一个密文块在密文中的起始索引
    prev_block_start = 16 + (block_idx - 1) * 16
    target_block = ciphertext[prev_block_start:prev_block_start+16]

for i in range(len(target)):
    old = original[pos + i]
    new = target[i]
    if old != new:
        target_block[offset + i] ^= old ^ new

if block_idx == 0:
    ciphertext[:16] = target_block
else:
    ciphertext[prev_block_start:prev_block_start+16] = target_block

new_plain = decrypt(bytes(ciphertext))
print("篡改后:", new_plain)
if b";admin=true" in new_plain:
    print("成功")