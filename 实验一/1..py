import base64
hex_str = "49276d206b696c6c696e6720796f757220627261696e2e"
result = base64.b64encode(bytes.fromhex(hex_str)).decode()
print(result)