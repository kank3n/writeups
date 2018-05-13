# question
```
ELF Crumble

We prepared this beautiful binary that just printed for you the welcome flag, but it fell on the ground and broke into pieces.

Luckily no instruction was broken, so I am sure you can just glue it back together…

Flag format is non-standard, there are no brackets.

Files:

    pieces.tgz
```

# solution
We have one "broken" elf file and some fragmented files.
```
$ ls
broken  fragment_1.dat  fragment_2.dat  fragment_3.dat  fragment_4.dat  fragment_5.dat  fragment_6.dat  fragment_7.dat  fragment_8.dat
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
c3                   	ret  
```

I begun to play a piece of puzzle. I tried to combine sequences of bytes from prologue and those of bytes up to epilogue, and what size.

Function `f1`, `f2` and `f3` are very straightforward.

`f1`: fragment_8.dat fragment_7.dat fragment_1.dat(first 3 bytes)
`f2`: fragment_1.dat(4th byte - 72nd byte)
`f3`: fragment_1.dat(last 7 bytes) fragment_5.dat(up to 109th byte)

But, function `recover_flag` and `main` are troublesome.

`recover_flag`: fragment_5.dat(from 110th byte)
`main`:

```
$ xxd -r -p answer.txt > answer
$ chmod +x answer
$ ./answer 
welcOOOme
Segmentation fault
```

