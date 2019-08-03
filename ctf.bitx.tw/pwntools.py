#!/usr/bin/env python2
from pwn import *
import re

# init
c = remote('ctf.bitx.tw', 10103)
fm = r'(\d+) *([+\-*]) *(\d+)'

# drop
print(c.recvuntil('JOJO !!!\n'))

# Complete
for x in range(100):
    print(x)
    for i in range(0, 10):
        get = c.recvline()
        ans = str(eval(get))
        #print(get + '=' + ans)
        c.sendline(ans)

print("get")
c.interactive()

c.close()
