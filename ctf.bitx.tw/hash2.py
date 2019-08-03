#!/usr/bin/env python
import hashlib
import re
r = r'^0+e[0-9]*$'

def hash1(data):
    step1 = hashlib.md5(str(data).encode('utf-8')).hexdigest()
    return  hashlib.md5(str(step1).encode('utf-8')).hexdigest()

def hash2(data):
    step1 = hashlib.sha1(str(data).encode('utf-8')).hexdigest()
    return  hashlib.sha1(str(step1).encode('utf-8')).hexdigest()

def hash3(data):
    return  hashlib.md5(data.encode('utf-8')).hexdigest()

i = 0
while not re.match(r, hash1(str(i) + 'what')):
    i += 1
print('md5md5:' + str(i))

i = 0
while not re.match(r, hash2(i)):
    i += 1
print('sha1sha1:' + str(i))

i = 0
while not re.match(r, hash3(str(i) + 'isthis')):
    i += 1
print('md6:' + str(i))
