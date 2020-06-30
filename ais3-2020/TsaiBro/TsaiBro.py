#!/usr/bin/env python
import subprocess
import string

drop = 'Terry...逆逆...沒有...學問...單純...分享...個人...生活...感觸...\n'

def ascii_to_output(str1):
    return subprocess.check_output(['./TsaiBro', str1]).decode("utf-8").replace(drop, '')

dict1 = {}
for char in string.printable:
    dict1[ascii_to_output(char)] = char
print(dict1)

with open('./TsaiBroSaid') as f:
    data = f.read().replace(drop, '').split("發財")
    data.pop(0)
    while len(data) >= 2:
        data1 = data.pop(0)
        data2 = data.pop(0)
        key = '發財' + data1 + '發財' + data2
        print(dict1[key],end='')

