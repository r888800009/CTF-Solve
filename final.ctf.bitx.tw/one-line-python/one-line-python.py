#!/usr/bin/env python
def hash(s):
    return (int(__import__('hashlib').sha224(s).hexdigest(),16)^int(__import__('hashlib').sha256(s).hexdigest(),16)^int(__import__('hashlib').sha384(s).hexdigest(),16)^int(__import__('hashlib').sha512(s).hexdigest(),16))&0xFFFFFFFF

rainbow = {}
for c1 in range(0, 128):
    for c2 in range(0, 128):
        str1 = chr(c1) + chr(c2)
        # print('{}: {}'.format(hash(str1.encode('utf-8')), str1))
        rainbow[str(hash(str1.encode('utf-8')))] = str1

with open('output') as f:
    for line in f:
        print(rainbow[line.strip()], end='')
