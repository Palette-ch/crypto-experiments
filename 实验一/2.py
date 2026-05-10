h1 = "1c0111001f010100061a024b53535009181c"
h2 = "686974207468652062756c6c277320657965"
print(bytes(a^b for a,b in zip(bytes.fromhex(h1), bytes.fromhex(h2))).hex())