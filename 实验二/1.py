from Crypto.Cipher import AES
import base64
from hashlib import sha1


def calculate_checksum(numbers, weights):
    """计算校验和"""
    return sum(n * w for n, w in zip(numbers, weights)) % 10


def sha1_hexdigest(data):
    """计算SHA-1哈希并返回十六进制字符串"""
    return sha1(data.encode()).hexdigest()


def odd_even_check(hex_string):
    """对16进制字符串进行奇偶校验"""
    binary_str = bin(int(hex_string, 16))[2:].zfill(len(hex_string) * 4)
    checked_str = ''.join(b + '1' if b.count('1') % 2 == 0 else b + '0' for b in
                          (binary_str[i:i + 7] for i in range(0, len(binary_str), 7)))
    return hex(int(checked_str, 2))[2:].zfill(16)


def add_parity_bits(hex_input):
    # 将十六进制输入转换为二进制字符串
    binary_str = bin(int(hex_input, 16))[2:].zfill(8 * ((len(hex_input) * 4 + 7) // 8))

    # 为每个 7 位的数据块添加奇偶校验位
    parity_bits = [
        binary_str[i:i + 7] + ('1' if binary_str[i:i + 7].count('1') % 2 == 0 else '0')
        for i in range(0, len(binary_str), 8)
    ]

    # 将二进制字符串转换回十六进制并返回
    return hex(int(''.join(parity_bits), 2))[2:]


def generate_key(h_d):
    """生成AES密钥"""
    ka = add_parity_bits(h_d[:16])  # 取前14个字符
    kb = add_parity_bits(h_d[16:32])  # 取接下来的14个字符
    return ka + kb  # 返回28个字符的字符串


def decrypt_aes_cbc(ciphertext, key):
    """AES CBC模式解密"""
    aes = AES.new(bytes.fromhex(key), AES.MODE_CBC, bytes.fromhex('0' * 32))
    return aes.decrypt(ciphertext).decode()


# 主逻辑
if __name__ == "__main__":
    # 步骤1
    # checksum = calculate_checksum([1,1,1,1,1,6], [7,3,1,7,3,1])

    # 步骤2
    passport = '12345678<8<<<1110182<1111167<<<<<<<<<<<<<<<4'
    mrz = passport[:10] + passport[13:20] + passport[21:28]
    h_mrz = sha1_hexdigest(mrz)
    # print(h_mrz)

    # 步骤3
    k_seed = h_mrz[:32]
    d = k_seed + '00000001'
    h_d = sha1(bytes.fromhex(k_seed + '00000001')).hexdigest()
    # print(h_d)
    # 步骤4
    key = generate_key(h_d)
    # key='ea8645d97ff725a898942aa280c43179'
    # print(key)

    # 步骤5
    cipher_text = base64.b64decode(
        '9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI')
    result = decrypt_aes_cbc(cipher_text, key)
    print(result)
    #Herzlichen Glueckwunsch. Sie haben die Nuss geknackt. Das Codewort lautet: Kryptographie!