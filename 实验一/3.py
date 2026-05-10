def score(b):
    return sum(1 for x in b if x in b'etaoinshrdlcumwfgypbvkjxqz ')

cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
data = bytes.fromhex(cipher)
key = max(range(256), key=lambda k: score(bytes(x^k for x in data)))
print(f"密钥：{key}，明文：{bytes(x^key for x in data).decode()}")