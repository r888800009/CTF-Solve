#!/usr/bin/env python2
from pwn import *
import re

# init
c = remote('isc.taiwan-te.ch', 9999)
fm = r'(\d+) *([+\-*]) *(\d+)'

# magic
print(c.recvline())
c.send(p32(3735928559))
print(c.recvline())

# Complete
for i in range(0, 1000):
    get = c.recvuntil('= ?', drop=True)
    ans = str(eval(get))
    c.sendline(ans)

# get shell
getline = c.recvline()
print("get")
c.interactive()

c.close()
