#!/usr/bin/env python
import socket
import time
import string

from multiprocessing import Process, Manager


def try_string(ans):
    ans = ans.encode()
    t_start = time.time()

    buf_size = 1024
    s = socket.socket()
    s.connect(("hackme.inndy.tw", 7708))
    s.sendall(ans + b'\n')
    while not b'Bye' in s.recv(buf_size):
        continue

    return time.time() - t_start

def try_new_char(args):
    ans = args[0]
    test_char = args[1]


# flag has no lowercase or space,
# and should match this regex: FLAG\{[0-9A-Z_]+\}
charset = string.ascii_uppercase + string.digits + '_}'
ans = 'FLAG{'
# ans = 'FLAG{2_SLOW_I_M_GOING_TO_SL33P'

while True:
    print(ans)

    # test base time
    base_time = try_string(ans)

    def t_func(new_char, c, base_time):
        if try_string(ans + c) - base_time > 0.5:
            if new_char[0] == '\0':
                new_char[0] = c
                return c
            else:
                raise Exception('Error')

    # test charset
    procs = []
    m = Manager()
    new_char = m.list(range(1))
    new_char[0] = '\0'
    for c in charset:
        p = Process(target=t_func, args=(new_char, c, base_time))
        p.start()
        procs.append(p)

    for p in procs:
        p.join()

    if new_char[0] == '\0':
        print(ans)
        break

    ans += new_char[0]
    print(ans)


