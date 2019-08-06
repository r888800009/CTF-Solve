#!/usr/bin/env python
import hashlib

md5 = hashlib.md5
sha256 = hashlib.sha256

# flag
flag_md5s = [22, 3, 5, 8, 12, 20, 43, 0, 0, 33, 0, 43, 19, 0, 5, 0, 0, 33, 5, 43, 0, 3, 33, 0, 0, 5, 3, 0, 43, 0, 11, 16, 0, 29, 11, 43, 0, 5, 0, 5, 16, 0, 0, 7, 11, 43, 5, 23]
flag_sha256s = [19, 47, 40, 1, 13, 30, 3, 5, 6, 28, 22, 3, 10, 6, 49, 5, 6, 28, 19, 8, 5, 40, 28, 6, 22, 19, 40, 6, 8, 5, 2, 24, 22, 9, 15, 3, 5, 19, 6, 49, 44, 5, 6, 10, 15, 3, 49, 0]
flag = list(zip(flag_md5s, flag_sha256s))

# gen table
cand = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890@,- _{}'

md5s = []
sha256s = []

for c in cand:
    md5s.append(int(md5(c.encode()).hexdigest(), 16) % 50)
    sha256s.append(int(sha256(c.encode()).hexdigest(), 16) % 50)

table = dict(zip(zip(md5s, sha256s), cand))

# print flag
for f in flag:
    print(table[f], end='')
print()

