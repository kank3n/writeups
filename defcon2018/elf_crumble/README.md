I enjoyed this challenge and learned how to handle binary files.

# Question
```
ELF Crumble

We prepared this beautiful binary that just printed for you the welcome flag, but it fell on the ground and broke into pieces.

Luckily no instruction was broken, so I am sure you can just glue it back together…

Flag format is non-standard, there are no brackets.

Files:

    pieces.tgz
```

# Solution
We have one `broken` elf file and some fragmented files. I checked size of fragment files.
```
$ tar xvzf pieces.tgz
$ ls
broken  fragment_1.dat  fragment_2.dat  fragment_3.dat  fragment_4.dat  fragment_5.dat  fragment_6.dat  fragment_7.dat  fragment_8.dat
$ du -b fragment_*
79	fragment_1.dat
48	fragment_2.dat
175	fragment_3.dat
42	fragment_4.dat
128	fragment_5.dat
22	fragment_6.dat
283	fragment_7.dat
30	fragment_8.dat
```

I checked broken elf using `objdump` command. I found some functions padded with "58 pop eax" that should be fixed. I calculated how many bytes for each function.

```
000005ad <f1> 316 byte
000006e9 <f2>: 69 byte
0000072e <f3>: 116 byte
000007a2 <recover_flag>: 58 byte
000007dc <main>: 248 byte
```

Let's play with fragmented files now with `xxd` command.

```
$ xxd fragment_1.dat
0000000: 5b5d c355 89e5 83ec 10e8 e001 0000 05dc  [].U............
0000010: 1800 00c7 45fc 0000 0000 eb23 8b55 fc8b  ....E......#.U..
0000020: 4508 01d0 0fb6 0089 c28b 45fc 8d0c 028b  E.........E.....
0000030: 55fc 8b45 0801 d089 ca88 1083 45fc 0183  U..E........E...
0000040: 7dfc 137e d790 c9c3 5589 e553 83ec 14    }..~....U..S...
```

I searched sequences of bytes "5589e5" - function prologue - and "c9c3" - function epilogue.

**Function prologue**
```
55                   	push   ebp
89 e5                	mov    ebp,esp
 ```

**Function epilogue**
```
c9                   	leave  
c3                   	ret      <-- In somecase only this.
```

I begun to play a piece of puzzle. I tried to combine sequences of bytes from prologue and those of bytes up to epilogue, and what size.

Function `f1`, `f2` and `f3` are very straightforward.

* `f1`: fragment_8.dat + fragment_7.dat + fragment_1.dat(first 3 bytes)
* `f2`: fragment_1.dat(4th byte - 72nd byte)
* `f3`: fragment_1.dat(last 7 bytes) + fragment_5.dat(up to 109th byte)

But, function `recover_flag` and `main` are troublesome. I just combined below for `recover_flag` because size is total 58 bytes. 

* `recover_flag`: fragment_5.dat(last 19 bytes) + fragment_6.dat + fragment_2.dat(first 17 bytes)

In order to make it sure, I dumped it to hex and paste it to [ODA](https://onlinedisassembler.com/odaweb/). It seems to be very organized and I was sure this function works.

```
$ cat fragment_5.dat fragment_6.dat fragment_2.dat > recover_flag
$ xxd -p recover_flag 
e89a010000059618000083ec0cff750889c3e8f4fcffff83c4108945f4c7
45f000000000eb2d8b55f08b450801d00fb6088b45f001c0ba6d00000029
c289d089c38b55f08b450801d009d989ca88108345f0018b45f489c2c1ea
1f01d0d1f883e8043945f07cbf908b5dfcc9c3 (snip)5589e583ec08e827010000
0523180000ff7508e8f3fdffff83c40483ec0cff7508e866ffffff83c410
83ec0cff7508e813ffffff83c41090c9c3(snip) 8d4c240483e4f0ff71fc5589e5
5756535183ec38e8bbfcffff81c3db170000
```
![2018-05-13 12 24 45](https://user-images.githubusercontent.com/9530961/39963530-a8e938d8-56a8-11e8-9d04-8fd198bba3b3.png)


`main` is more complexed. Total size of the combination below is 248 byes that must be `main` function size.

* `main`: fragment_2.dat(last 31 bytes) + fragment_3.dat + fragment_4.dat

However, I suspected how to handle 10 bytes below just before prologue in `fragment_2.dat`.

```
$ xxd -p fragment_2.dat 
83ec0cff7508e813ffffff83c41090c9c3 (snip)8d4c240483e4f0ff71fc(snip) 5589e5
5756535183ec38e8bbfcffff81c3db170000
```

I just combined files and go to [ODA](https://onlinedisassembler.com/odaweb/) again.
```
$ cat fragment_2.dat fragment_3.dat fragment_4.dat > main
$ xxd -p main
83ec0cff7508e813ffffff83c41090c9c3 (snip)8d4c240483e4f0ff71fc5589e5
5756535183ec38e8bbfcffff81c3db17000089c88b40048945c465a11400
00008945e431c0c745cd44696420c745d1596f7520c745d546696e44c745
d920746865c745dd20476c5566c745e1653fc645e300c745c80100000083
ec0c8d45cd50e854ffffff83c4100fb645e10fbec80fb645cd0fbef80fb6
45d80fbec08945c00fb645d80fbed08955bc0fb645d80fbef08975b80fb6
45ce0fbef00fb645e10fbed00fb645d50fbec083ec0c5157ff75c0ff75bc
ff75b85652508d83b0e9ffff50e871fbffff83c430b8000000008b7de465
333d140000007405e8880000008d65f0595b5e5f5d8d61fcc3(snip)
```

10 bytes stand for first three lines instruction. These instruction executes save return address and stack alignment. Therefore, it just stay here and may work!

![2018-05-13 12 08 00](https://user-images.githubusercontent.com/9530961/39963472-9f2c3496-56a6-11e8-96f5-6a02d3090aa9.png)

These are complete each function's paload.

* f1  
5589e55383ec10e81b03000005171a00008b903800000089d18b550801ca
0fb6128855fb8b903800000089d18b550801ca0fb6128d4a028b90380000
0089d38b550801da880a8b90380000008d4a028b550801d10fb655fb8811
8b903c00000089d18b550801ca0fb6128855fb8b903c00000089d18b5508
01ca0fb6128d4a038b903c00000089d38b550801da880a8b903c0000008d
4a038b550801d10fb655fb88118b904000000089d18b550801ca0fb61288
55fb8b904000000089d18b550801ca0fb6128d4a048b904000000089d38b
550801da880a8b90400000008d4a048b550801d10fb655fb88118b904400
000089d18b550801ca0fb6128855fb8b904400000089d18b550801ca0fb6
128d4a058b904400000089d38b550801da880a8b80440000008d50058b45
0801c20fb645fb88029083c4105b5dc3

* f2  
5589e583ec10e8e001000005dc180000c745fc00000000eb238b55fc8b45
0801d00fb60089c28b45fc8d0c028b55fc8b450801d089ca88108345fc01
837dfc137ed790c9c3

* f3  
5589e55383ec14e89a010000059618000083ec0cff750889c3e8f4fcffff
83c4108945f4c745f000000000eb2d8b55f08b450801d00fb6088b45f001
c0ba6d00000029c289d089c38b55f08b450801d009d989ca88108345f001
8b45f489c2c1ea1f01d0d1f883e8043945f07cbf908b5dfcc9c3

* recover_flag  
5589e583ec08e8270100000523180000ff7508e8f3fdffff83c40483ec0c
ff7508e866ffffff83c41083ec0cff7508e813ffffff83c41090c9c3

* main  
8d4c240483e4f0ff71fc5589e5
5756535183ec38e8bbfcffff81c3db17000089c88b40048945c465a11400
00008945e431c0c745cd44696420c745d1596f7520c745d546696e44c745
d920746865c745dd20476c5566c745e1653fc645e300c745c80100000083
ec0c8d45cd50e854ffffff83c4100fb645e10fbec80fb645cd0fbef80fb6
45d80fbec08945c00fb645d80fbed08955bc0fb645d80fbef08975b80fb6
45ce0fbef00fb645e10fbed00fb645d50fbec083ec0c5157ff75c0ff75bc
ff75b85652508d83b0e9ffff50e871fbffff83c430b8000000008b7de465
333d140000007405e8880000008d65f0595b5e5f5d8d61fcc3

In end of the game, I paseted payloads above into hex file from `broken` and reverted it. `xxd` is very powerful tool. It does'nt care of space and a new line when it revert text to binary. So you can just roughly paste!

```
$ xxd -p broken > answer.txt

Edit answer.txt and replace "58" with payloads above.

$ xxd -r -p answer.txt > answer
$ chmod +x answer
$ ./answer 
welcOOOme
```

So flag is "welcOOOme".


