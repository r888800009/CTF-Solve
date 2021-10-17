#!/usr/bin/env python3
from pwn import *
import sys
import pwnlib.shellcraft
import pwnlib
import time

context.os='linux'
context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']

context.log_level = 100
#context.log_level = 'debug'


pwn_file = "./ANALYZER"
elf = ELF(pwn_file)


for i in range(0, 0xff):
    print(i)
    c = process(pwn_file)
    c.sendafter('Enter your passcode:', 'p4xz30f6?*' + chr(i))
    payload = b'1,31,16,11,m\r\n'
    payload += b'2,5s,h,c,4\r\n'
    payload += b'3,6x,9,b,15\r\n'
    payload += b'4,6t,b,7,1c\r\n'
    payload += b'5,73,k,t,z\r\n'
    payload += b'6,5z,1d,e,g\r\n'
    payload += b'7,3z,r,17,u\r\n'
    payload += b'8,3x,q,3,19'

    payload = b'1,31,16,11,m\r\n'
    c.sendafter(' format:', payload)
    try:
        print(c.recv(1000))
        c.close()
    except EOFError as error:
        pass

