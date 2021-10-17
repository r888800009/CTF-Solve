#!/usr/bin/env python3
from pwn import *
import sys
import pwnlib.shellcraft
import pwnlib

c = 0
pwn_file = "./pwntools"
elf = ELF(pwn_file)
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
context.log_level = 'debug'
#c = process(pwn_file)
c = remote('140.110.112.77', '2116')
c.sendafter('Give me the magic :)\n', p32(0x79487ff))

# Hacker can complete 1000 math problems in 60s, prove yourself.
c.recvline()

for i in range(1000):
    #line = c.recvline()
    line = c.recvuntil('?').split()
    opd1 = int(line[0].decode())
    opd2 = int(line[2].decode())
    opr = line[1]

    if opr == b'+':
        c.sendline(str(opd1 + opd2))
    elif opr == b'-':
        c.sendline(str(opd1 - opd2))
    elif opr == b'*':
        c.sendline(str(opd1 * opd2))


c.interactive()
c.close()
