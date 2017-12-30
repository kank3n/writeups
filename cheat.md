# cheat sheet
'''
$ vi main.sh
gdbserver localhost:1234 ./hacknote
$ chmod +x main.sh
$ socat TCP-LISTEN:10102,reuseaddr,fork EXEC:"./main.sh"
'''
-
$ vi cmd
file ./hacknote
target remote localhost:1234
c
$ gdb ./hacknote -q -x cmd
