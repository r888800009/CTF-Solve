#!/usr/bin/env python

string ='49 51 5b 3b 4b 72 85 68 83 87 3b 72 6b 3e 7d 3b 6f 47 3e 6f 47 76 3b 6f 87 3e 78 72 6a 6f 3e 74 6f 78 3b 84 3b 78 7b 39 7c 77 29 29 29 8d'
string = string.split()
out = ''
for s in string:
    print(s)
    for i in range(0xff):
        if i + 0xb ^ 5 ==  int(s, 16):
            out += chr(i)
print(out)
