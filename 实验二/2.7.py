def pkcs7_validate(data: bytes) -> bool:
    """
    验证 PKCS#7 填充是否有效。
    返回 True 表示填充正确，否则 False。
    """
    if not data:
        return False
    pad_len = data[-1]
    # 填充长度必须在 1 到 16 之间（块大小假设为16）
    if pad_len < 1 or pad_len > 16:
        return False
    # 数据长度必须至少能容纳填充
    if len(data) < pad_len:
        return False
    # 检查最后 pad_len 个字节是否都是 pad_len
    return all(data[-i] == pad_len for i in range(1, pad_len + 1))

# 测试用例
test_cases = [
    (b"ICE ICE BABY\x04\x04\x04\x04", True),   # 正确填充
    (b"ICE ICE BABY\x05\x05\x05\x05", False),  # 长度错（应该是4却写了5）
    (b"ICE ICE BABY\x01\x02\x03\x04", False),  # 填充值不一致
    (b"ICE ICE BABY\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10", True),  # 完整块填充
]

for data, expected in test_cases:
    result = pkcs7_validate(data)
    print(f"{data!r} -> {result} (期望: {expected})")
    assert result == expected
print("所有测试通过！")