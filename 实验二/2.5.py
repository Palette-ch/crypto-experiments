from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = b'\xc6\xfe\xe2/\x97r|/\xeaY\x85C\xbfi\x99\x97'

def profile_for(email: str) -> bytes:
    email = email.replace('&', '').replace('=', '')
    return f"email={email}&uid=10&role=user".encode()

def encrypt(email: str) -> bytes:
    return AES.new(KEY, AES.MODE_ECB).encrypt(pad(profile_for(email), 16))

def decrypt(ct: bytes) -> str:
    return unpad(AES.new(KEY, AES.MODE_ECB).decrypt(ct), 16).decode()

# 构造包含 "admin" 的块
# 我们需要让 "admin" 恰好占据一个完整的16字节块，并且前面没有任何干扰
# 通过构造 email = "A"*10 + "admin" + 填充，使得加密后的第二个块就是 admin 块
email_admin = "A" * 10 + "admin" + "\x0b" * 11   # 总长度 10+5+11=26，不是16的倍数，但 padding 会处理
ct_admin = encrypt(email_admin)
# 第二个块（16:32）就是 admin + 填充
admin_block = ct_admin[16:32]

# 正常用户：email = "A"*13，加密后长度应为48字节（3个块）
# 结构: block0: email=AAAAAAAAAAA, block1: A&uid=10&role=, block2: user + padding
ct_normal = encrypt("A" * 13)
# 替换 block2 为 admin_block
evil_ct = ct_normal[:32] + admin_block + ct_normal[48:]

# 验证
result = decrypt(evil_ct)
print(result)
assert "role=admin" in result
print("攻击成功！")