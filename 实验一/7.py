#coding:utf-8
import hashlib
import itertools
import datetime

def sha_encrypt(str):
    sha = hashlib.sha1(str.encode())
    encrypts = sha.hexdigest()
    return encrypts

def dfs(idx, path, str2, hash1):
    if idx == len(str2):
        for p in itertools.permutations(path):
            if sha_encrypt("".join(p)) == hash1:
                print("Password:","".join(p))
                print("Runing Time:"+str(datetime.datetime.now() - starttime)+"s")
                return True
        return False
    for i in range(2):
        if dfs(idx + 1, path + [str2[idx][i]], str2, hash1):
            return True
    return False

starttime = datetime.datetime.now()
hash1 = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"
str2 = [['Q', 'q'], ['W', 'w'], ['%', '5'], ['8', '('], ['=', '0'], ['I', 'i'], ['*', '+'], ['n', 'N']]
dfs(0, [], str2, hash1)