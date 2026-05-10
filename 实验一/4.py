def score(b):
    # 直接对字节评分
    freq = b'etaoinshrdlcumwfgypbvkjxqz '
    return sum(1 for x in b if x in freq)

def decrypt(line):
    d = bytes.fromhex(line.strip())
    best_score = -1
    best_text = ""
    for k in range(256):
        plain_bytes = bytes(c ^ k for c in d)
        sc = score(plain_bytes)
        if sc > best_score:
            best_score = sc
            # 加errors='ignore'，忽略无法解码的字节
            best_text = plain_bytes.decode('utf-8', errors='ignore')
    return best_text, best_score

if __name__ == "__main__":
    best = ""
    max_sc = -1
    with open("4.txt", "r", encoding="utf-8") as f:
        lines = f.readlines()

    for line in lines:
        text, sc = decrypt(line)
        if sc > max_sc:
            max_sc = sc
            best = text
    print("结果：", best)