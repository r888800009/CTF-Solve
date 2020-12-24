#!/usr/bin/env python3
from pwn import *
import sys
import pwnlib.shellcraft
import pwnlib
import time

c = 0
pwn_file = "./re-alloc"
lib_file = './libc-2.29.so'

elf = ELF(pwn_file)
lib = ELF(lib_file)
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
context.log_level = 'debug'

debug = 1
if debug == 1:
    ld_str = "{} --library-path ./ {}".format(lib_file, pwn_file)
    print(ld_str.split())
    c = process(ld_str.split(), env={'LD_PRELOAD': lib_file})

    elf_path = c.cwd + c.argv[3].decode().strip('.')
    lib_path = c.cwd + lib_file.strip('.')

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
    c = remote('', '')


c.interactive()
c.close()

