#!/usr/bin/env python
import hashlib
def hash(data):
    for i in range(15):
        data = hashlib.md5(str(data).encode('utf-8')).hexdigest()
    return data

for i in range(128):
    if hash(chr(i)) == "34628a5551eb88b8d05985398dd8ba9b":
        print('NTIHS{' + chr(i) + '}')

