#!/usr/bin/env python2
from pwn import *
import re

# init
c = remote('final.ctf.bitx.tw', 30003)

# drop
c.recvuntil('\n', drop=True)
c.recvuntil('\n', drop=True)

# Complete
for i in range(0, 500):
    get = c.recvuntil('=', drop=True)
    ans = str(eval(get))
    print(get)
    print(ans)
    c.sendline(ans)
    print(c.recvuntil('Answer =', drop=False))

# get flag
getline = c.recvline()
print(getline)
c.close()
