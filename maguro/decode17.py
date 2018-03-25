import struct
def p(a):
    return struct.pack("B",a)

text = [0x4d,0xfa,0xb,0x29,0xbe,0x36,0xf8,0xc9,0x2f,0xf,0x1,0xf0,0x5,0xcf,0x39,0xcb,0x2a,0xfe,0xd4,0x3b,0xd5,0x2c,0xd5,0x21,0xcc,0x1,0x4b]

for i in range(len(text)):
    if i == 0:
        buf = p(text[i])
    elif i == 1:
        if text[i]+text[i-1] > 0xff:
            tmp = text[i]+text[i-1]
            buf += p(tmp-0xff-1)
        else:
            tmp = text[i]+text[i-1]
            buf += p(tmp)
    else:
        if text[i]+tmp > 0xff:
            buf += p(text[i]+tmp-0xff-1)
            tmp = text[i]+tmp-0xff-1
        else:
            buf += p(text[i]+tmp)
            tmp = text[i]+tmp

print buf
