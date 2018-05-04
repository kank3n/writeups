# cheat sheet
```
$ vi main.sh
gdbserver localhost:1234 ./a.out
$ chmod +x main.sh
$ socat TCP-LISTEN:10001,reuseaddr,fork EXEC:"./main.sh"
```
```
$ vi cmd
file ./a.out
target remote localhost:1234
c
$ gdb ./hacknote -q -x cmd
```
