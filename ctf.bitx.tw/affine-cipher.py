#!/usr/bin/env python
import sys
import math

a = sys.argv[1]
b = sys.argv[2]
ciphertext = sys.argv[3]

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

print('cipher: ' + ciphertext)
encrypt = '(' + a + ' * x + ' + b + ') % 26'
invmod = modinv(int(a), 26)
decrypt = '(x - ' + b + ') * ' + str(invmod) + ' % 26'
print('e = ' +  encrypt)
print('e = ' +  decrypt)


def char_decoding(char1):
   x = ord(char1) - ord('a')
   y = eval(decrypt) + ord('a')
   return chr(y)


for c in ciphertext:
    print (char_decoding(c), end='')
print()
