import time, random
from string import printable


seed = 1582119378
random.seed(seed)

def rand():
    rnd = int(random.random() * (10 ** 5))
    while rnd:
        random.random()
        rnd -= 1
    return int(random.random() * 10 ** 5) & ((1 << 16) - 1)
    
def calc(ch, rnd):
    high = ch >> 4
    low = ch & 0xF

    _00 = (low << 4) | low
    _01 = (low << 4) | high
    _10 = (high << 4) | low
    _11 = (high << 4) | high
    
    val = 0
    val |= _00 << 12
    val |= _11 << 8
    val |= _01 << 4
    val |= _10 << 0

    res = 0
    res |= 0b0000111100001111 & (val ^ rnd)
    res |= 0b1111000011110000 & (val ^ rnd)
    res |= 0b0101010101010101 & (val ^ rnd)
    res |= 0b1010101010101010 & (val ^ rnd)

    return bin(res).lstrip('0b').zfill(16)

def all_different(val):
    lst = []
    for ch in printable:
        lst.append(calc(ord(ch), val))
    return len(lst) == len(set(lst))

with open('out.txt') as f:
    for line in f:
        # print(line.strip())
        _rand = rand()
        for i in range(0,256):
            assert(all_different(_rand))
            res = calc(i, _rand)
            if res == line.strip():
                print(chr(i), end='')
