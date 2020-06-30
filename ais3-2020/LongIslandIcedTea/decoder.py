#!/usr/bin/env python
import subprocess
import string

flag = '850a2a4d3fac148269726c5f673176335f6d335f55725f49475f346e645f746831735f31735f6d316e655f746572727974657272795f5f7d0000000000000000'

flag_part1 = flag[:8 * 2]
flag_part2 = flag[8 * 2:]
print(flag_part1)
print(bytearray.fromhex(flag_part2).decode())


prefix = "AIS3{"
drap = 'My encryptor 0.1\nI didn\'t implement the decryptor\nSo,you\'ll never find out my secret unless I am drunk'

def ascii_to_output(str1):
    return subprocess.check_output(['./Long_Island_Iced_Tea', str1]).decode("utf-8").replace(drop, '')

