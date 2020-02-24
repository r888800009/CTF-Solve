#!/usr/bin/env python
import binascii
from pwn import *

with open('corrupted_png.png', 'rb') as f:
    data = f.read()
    for i in range(2 ** 16):
        idch = data[12:16]
        width = data[16:20]
        height = p32(i, endian='big')
        ihdr_info = data[24:29]
        crc32 = binascii.crc32(idch + width + height + ihdr_info) & 0xffffffff
        if crc32 == 0x797d8e75:
            print(i)

