pt = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = b"ICE"
print(bytes(pt[i]^key[i%3] for i in range(len(pt))).hex())