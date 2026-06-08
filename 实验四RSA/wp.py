import os
import math
from Crypto.Util.number import inverse

# ==================== 路径配置 ====================
BASE_DIR = os.path.join("实验四RSA", "附件3-2（发布截获数据）")

# ==================== 工具函数 ====================
def int_to_bytes(n: int) -> bytes:
    """整数转字节串（大端）"""
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def extract_plaintext(padded: bytes) -> str:
    """从填充后的512比特消息中提取最后8字节作为明文"""
    return padded[-8:].decode('ascii', errors='ignore')

def load_frame_data():
    """加载所有Frame文件，返回 N_list, e_list, c_list"""
    N_list = []
    e_list = []
    c_list = []
    for i in range(21):
        filename = os.path.join(BASE_DIR, f"Frame{i}")   # 注意：无前导零
        try:
            with open(filename, 'r') as f:
                content = f.read().strip().replace(' ', '').replace('\n', '')
                if len(content) >= 768:
                    n_hex = content[:256]
                    e_hex = content[256:512]
                    c_hex = content[512:768]
                    N_list.append(int(n_hex, 16))
                    e_list.append(int(e_hex, 16))
                    c_list.append(int(c_hex, 16))
                else:
                    print(f"警告: {filename} 内容不足")
                    N_list.append(0); e_list.append(0); c_list.append(0)
        except FileNotFoundError:
            print(f"错误: {filename} 不存在")
            N_list.append(0); e_list.append(0); c_list.append(0)
    return N_list, e_list, c_list

# ==================== 攻击方法 ====================
def common_modulus_attack(N, e1, c1, e2, c2):
    """公共模数攻击"""
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)
    g, u, v = egcd(e1, e2)
    if g != 1:
        return None
    if u < 0:
        c1 = pow(c1, -1, N)
        u = -u
    if v < 0:
        c2 = pow(c2, -1, N)
        v = -v
    m = (pow(c1, u, N) * pow(c2, v, N)) % N
    return m

def factor_collision(n_list):
    """因数碰撞：两两求gcd"""
    for i in range(len(n_list)):
        if n_list[i] == 0:
            continue
        for j in range(i+1, len(n_list)):
            if n_list[j] == 0:
                continue
            g = math.gcd(n_list[i], n_list[j])
            if 1 < g < n_list[i]:
                return i, j, g
    return None, None, None

def chinese_remainder(moduli, remainders):
    """中国剩余定理"""
    total = 0
    prod = 1
    for m in moduli:
        prod *= m
    for m, r in zip(moduli, remainders):
        p = prod // m
        total += r * pow(p, -1, m) * p
    return total % prod, prod

def integer_nth_root(num, n):
    """整数开n次方（二分法）"""
    if num < 0:
        return None
    if num == 0:
        return 0
    low, high = 1, 1
    while high ** n <= num:
        high <<= 1
    while low < high:
        mid = (low + high + 1) // 2
        if mid ** n <= num:
            low = mid
        else:
            high = mid - 1
    if low ** n == num:
        return low
    return None

def broadcast_attack(n_list, c_list, e):
    """低指数广播攻击"""
    m_e, _ = chinese_remainder(n_list, c_list)
    m = integer_nth_root(m_e, e)
    return m

def fermat_factor(n):
    """费马分解法"""
    a = math.isqrt(n)
    if a * a == n:
        return a, a
    while True:
        a += 1
        b2 = a*a - n
        b = math.isqrt(b2)
        if b*b == b2:
            return a - b, a + b

def pollard_p_minus_1(n, B=1000000):
    """Pollard's p-1 分解法"""
    a = 2
    for i in range(2, B+1):
        a = pow(a, i, n)
        d = math.gcd(a-1, n)
        if 1 < d < n:
            return d
    return None

def decrypt_with_pq(N, e, c, p, q):
    """给定p,q解密"""
    phi = (p-1)*(q-1)
    d = inverse(e, phi)
    m_padded = pow(c, d, N)
    return int_to_bytes(m_padded)

# ==================== 主程序 ====================
def main():
    N_list, e_list, c_list = load_frame_data()
    decrypted = {}

    # 1. 公共模数攻击（Frame0 和 Frame4 假设相同N）
    if N_list[0] != 0 and N_list[4] != 0 and N_list[0] == N_list[4]:
        m = common_modulus_attack(N_list[0], e_list[0], c_list[0], e_list[4], c_list[4])
        if m:
            plain = extract_plaintext(int_to_bytes(m))
            decrypted[0] = plain
            print(f"Frame0 (公共模数攻击): {plain}")

    # 2. 因数碰撞
    i, j, g = factor_collision(N_list)
    if i is not None:
        print(f"因数碰撞: Frame{i} 和 Frame{j} 公因数 = {hex(g)}")
        # 解密Frame i
        p = g
        q = N_list[i] // p
        plain_bytes = decrypt_with_pq(N_list[i], e_list[i], c_list[i], p, q)
        plain = extract_plaintext(plain_bytes)
        decrypted[i] = plain
        print(f"Frame{i} (因数碰撞): {plain}")
        # 解密Frame j
        p2 = g
        q2 = N_list[j] // p2
        plain_bytes2 = decrypt_with_pq(N_list[j], e_list[j], c_list[j], p2, q2)
        plain2 = extract_plaintext(plain_bytes2)
        decrypted[j] = plain2
        print(f"Frame{j} (因数碰撞): {plain2}")

    # 3. 低指数广播攻击（e=5）
    e_small = 5
    broadcast_frames = [3, 8, 12, 16, 20]
    n_small = []
    c_small = []
    for f in broadcast_frames:
        if N_list[f] != 0 and e_list[f] == e_small:
            n_small.append(N_list[f])
            c_small.append(c_list[f])
    if len(n_small) >= 3:
        m = broadcast_attack(n_small, c_small, e_small)
        if m:
            plain = extract_plaintext(int_to_bytes(m))
            for f in broadcast_frames:
                decrypted[f] = plain
            print(f"广播攻击 (e={e_small}): {plain}")
        else:
            print("广播攻击失败")
    else:
        print(f"广播攻击条件不足，只有 {len(n_small)} 个帧")

    # 4. 费马分解法（Frame10, Frame14）
    for idx in [10, 14]:
        if N_list[idx] != 0:
            try:
                p, q = fermat_factor(N_list[idx])
                plain_bytes = decrypt_with_pq(N_list[idx], e_list[idx], c_list[idx], p, q)
                plain = extract_plaintext(plain_bytes)
                decrypted[idx] = plain
                print(f"Frame{idx} (费马分解法): {plain}")
            except Exception as e:
                print(f"Frame{idx} 费马分解失败: {e}")

    # 5. Pollard's p-1 分解法（Frame2, Frame6, Frame19）
    for idx in [2, 6, 19]:
        if N_list[idx] != 0:
            p = pollard_p_minus_1(N_list[idx])
            if p:
                q = N_list[idx] // p
                plain_bytes = decrypt_with_pq(N_list[idx], e_list[idx], c_list[idx], p, q)
                plain = extract_plaintext(plain_bytes)
                decrypted[idx] = plain
                print(f"Frame{idx} (Pollard p-1): {plain}")
            else:
                print(f"Frame{idx} Pollard p-1 失败")

    # 输出结果
    print("\n" + "="*50)
    print("已破解明文片段（按帧序号）:")
    for idx in sorted(decrypted.keys()):
        print(f"Frame{idx:02d}: {decrypted[idx]}")

    # 简单拼接（实际应按通信序号排序，此处仅示例）
    full = ''.join(decrypted.get(i, '') for i in range(21))
    print("\n拼接结果（帧序号顺序）:\n", full)

if __name__ == "__main__":
    # 检查目录是否存在
    if not os.path.exists(BASE_DIR):
        print(f"错误：目录不存在 - {BASE_DIR}")
        print(f"当前工作目录: {os.getcwd()}")
    else:
        main()