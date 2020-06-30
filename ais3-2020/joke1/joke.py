#!/usr/bin/env python
import subprocess
from itertools import permutations
import string

list1 = []
for i in range(0,256):
    if chr(i) in string.whitespace:
        continue
    list1.append(i)

for i in permutations(list1, 6):
    print(i)
    ans = ''.join([chr(c) for c in i])
    ans = ans[::-1]
    print(ans)
    p = subprocess.Popen('./joke', stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    p.stdin.write(str.encode(ans))
    p.stdin.flush()
    p.stdout.flush()
    print(p.stdout.read())
    p.wait()
