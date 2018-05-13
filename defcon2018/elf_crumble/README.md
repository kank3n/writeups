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

```
$ xxd -r -p answer.txt > answer
$ chmod +x answer
$ ./answer 
welcOOOme
Segmentation fault
```
