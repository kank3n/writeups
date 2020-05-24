from pwn import *

context(os='linux', arch='amd64')
context.log_level = 'debug'

host = ""
port = 1337
bin = ""

gdbscript = '''
    break main
    continue
'''

if len(sys.argv) > 1 and sys.argv[1] == '-r':
    c = remote(host, port)
else:
    c = process(bin)
    c = gdb.debug([bin], gdbscript=gdbscript)


c.interactive()
