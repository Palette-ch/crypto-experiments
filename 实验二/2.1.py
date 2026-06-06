def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    if not (1 <= block_size <= 255):
        raise ValueError("block_size must be 1..255")
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)

# 测试
msg = b"YELLOW SUBMARINE"
padded = pkcs7_pad(msg, 20)
print(padded.hex())   # 应输出 59454c4c4f57205355424d4152494e4510101010101010101010