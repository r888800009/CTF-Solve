#!/usr/bin/env python
from pwn import *
from z3 import *

c = remote('140.110.112.77', '9003')
context.log_level = 'debug'

while True:
    f1 = c.recvline().split()
    if len(f1) < 2:
        break
    f2 = c.recvline().split()
    print(f1)
    print(f2)

    x = Real('x')
    y = Real('y')

    s = Solver()
    s.add(int(f1[0]) * x  + int(f1[4]) * y == int(f1[8]), int(f2[0]) * x  + int(f2[4]) * y == int(f2[8]))

    print(s)
    print(s.check())
    m = s.model()

    c.sendlineafter('x = ', str(m.evaluate(x)))
    c.sendlineafter('y = ', str(m.evaluate(y)))


c.interactive()
c.close()
