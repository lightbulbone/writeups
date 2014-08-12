Game Site: leviathan.labs.overthewire.org

# Level 0

User: leviathan0
Pass: leviathan0

    leviathan0@melinda:~$ grep -i pass .backup/bookmarks.html 
    <DT><A HREF="http://www.goshen.edu/art/ed/teachem.htm" ADD_DATE="1146092098" LAST_CHARSET="ISO-8859-1" ID="98012771">Pass it
    <DT><A HREF="http://leviathan.labs.overthewire.org/passwordus.html | This will be fixed later, the password for leviathan1 is rioGegei8m" ADD_DATE="1155384634" LAST_CHARSET="ISO-8859-1" ID="rdf:#$2wIU71">password to leviathan1</A>
    leviathan0@melinda:~$

# Level 1

User: leviathan1
Pass: rioGegei8m

    leviathan1@melinda:~$ ./check 
    password: xes
    Wrong password, Good Bye ...
    leviathan1@melinda:~$ ./check 
    password: sex
    $ cat /etc/leviathan_pass/leviathan2
    ougahZi8Ta
    $ exit
    leviathan1@melinda:~$

The above works because the `check` program was setuid to leviathan2.  When the password was guessed correctly 
the program would drop into a shell running with the privileges of leviathan2.

        00 01 02 03
    EBP -- -- -- --
    +2c ?? ?? ?? ?? | %gs:0x14
    +28 64 6F 67 00 | g o d \0
    +24 73 65 78 00 | s e x \0
    +20
    +1c 76 6F 6C 00 | v o l 
    +18 74 65 00 65 | t e \0 e
    +14 73 65 63 72 | s e c r
    +10
    +0c
    +08
    +04
    +00
    ESP -- -- -- --
    
# Level 2

User: leviathan2
Pass: ougahZi8Ta

This level hinges on the use of `access()` and passing the given string to `cat`.  If we create two files, 
one that links to the password file and another with the same basename containing a space, we can trick `access()`.
This works because we ask `access()` to check the existence of our `file asdf` file which passes, then `cat` will
interpret the space as a filename delimiter and dereference our symlink rather than print the contents of 
`file asdf`.

    leviathan2@melinda:/tmp/lbo_1234_l2$ ll
    total 4336
    drwxrwxr-x    2 leviathan2 leviathan2    4096 Aug 12 22:30 ./
    drwxrwx-wt 7718 root       root       4423680 Aug 12 22:30 ../
    lrwxrwxrwx    1 leviathan2 leviathan2      30 Aug 12 22:30 file -> /etc/leviathan_pass/leviathan3
    -rw-rw-r--    1 leviathan2 leviathan2       0 Aug 12 22:30 file asdf
    leviathan2@melinda:/tmp/lbo_1234_l2$ cd
    leviathan2@melinda:~$ ltrace ./printfile /tmp/lbo_1234_l2/file\ asdf
    __libc_start_main(0x80484f4, 2, -10316, 0x80485d0, 0x8048640 <unfinished ...>
    access("/tmp/lbo_1234_l2/file asdf", 4)                                                                                             = 0
    snprintf("/bin/cat /tmp/lbo_1234_l2/file a"..., 511, "/bin/cat %s", "/tmp/lbo_1234_l2/file asdf")                                   = 35
    system("/bin/cat /tmp/lbo_1234_l2/file a".../bin/cat: /tmp/lbo_1234_l2/file: Permission denied
    /bin/cat: asdf: No such file or directory
     <unfinished ...>
    --- SIGCHLD (Child exited) ---
    <... system resumed> )                                                                                                              = 256
    +++ exited (status 0) +++
    leviathan2@melinda:~$ ./printfile /tmp/lbo_1234_l2/file\ asdf
    Ahdiemoo1j
    /bin/cat: asdf: No such file or directory
    leviathan2@melinda:~$

# Level 3

User: leviathan3
Pass: Ahdiemoo1j

This level once again abuses the idea of setuid.  The comparison in this case is not done using `strcmp()` so 
you can't run ltrace/strace to see what the password is being compared too.  However, if you run `strings` on 
the program: 

    leviathan3@melinda:~$ strings level3 
    /lib/ld-linux.so.2
    __gmon_start__
    libc.so.6
    _IO_stdin_used
    __printf_chk
    puts
    __stack_chk_fail
    stdin
    fgets
    system
    __libc_start_main
    GLIBC_2.3.4
    GLIBC_2.4
    GLIBC_2.0
    PTRh0
    QVhP
    UWVS
    [^_]
    snlprintf
    [You've got shell]!
    /bin/sh
    bzzzzzzzzap. WRONG
    Enter the password> 
    ;*2$",
    secret
    leviathan3@melinda:~$

You will see the password disguised as a library call to `snlprintf`.  You can confirm this by running the 
program in GDB and analyzing the disassembly and register usage.  The password comparison in this level is 
done using the x86 `rep cmpsb` instruction.

    leviathan3@melinda:~$ ./level3 
    Enter the password> snlprintf 
    [You've got shell]!
    $ cat /etc/leviathan_pass/leviathan4
    vuH0coox6m
    $ exit
    leviathan3@melinda:~$

# Level 4

User: leviathan4
Pass: vuH0coox6m

This level just involves translating some binary numbers into the ASCII password.  Running ltrace you see that 
the setuid program at `~/.trash/bin` just reads the leviathan5 password file.  A simple ruby script can translate 
for us:

    2.1.2 :018 > [0b01010100, 0b01101001, 0b01110100, 0b01101000, 0b00110100, 0b01100011, 0b01101111, 0b01101011, 0b01100101, 0b01101001, 0b00001010].each { |c|
    2.1.2 :019 >     print c.chr
    2.1.2 :020?>   }
    Tith4cokei
     => [84, 105, 116, 104, 52, 99, 111, 107, 101, 105, 10]
     
# Level 5

User: leviathan5
Pass: Tith4cokei

Another straight forward level.  The idea here is that the setuid program `leviathan5` reads from a file called 
`/tmp/file.log`.  Because the program is setuid to `leviathan6` and the `fopen()` function follows symlinks, we 
just need to create a symlink to the password file and run the program.

    leviathan5@melinda:~$ echo asdfjkl > /tmp/file.log
    leviathan5@melinda:~$ ./leviathan5 
    asdfjkl
    leviathan5@melinda:~$ ln -s /etc/leviathan_pass/leviathan6 /tmp/file.log
    leviathan5@melinda:~$ ./leviathan5 
    UgaoFee4li
    leviathan5@melinda:~$
    
# Level 6

User: leviathan6
Pass: UgaoFee4li

This level is all about comparing numbers.  If you run the program without arguments it compalins that you need 
to give it a four digit number.  Running the program in GDB you can see where it does the comparison at offset 
0x0804851d.  Here you see the program compares your given number with that stored at `0x1c(%esp)`.  Looking back 
in the disassembly you see this set too 0x1bd3, our magic number.

    leviathan6@melinda:~$ gdb -q ./leviathan6 1234
    Reading symbols from /home/leviathan6/leviathan6...(no debugging symbols found)...done.
    Attaching to program: /home/leviathan6/leviathan6, process 1234
    ptrace: No such process.
    /home/leviathan6/1234: No such file or directory.
    (gdb) b main
    Breakpoint 1 at 0x80484d7
    (gdb) r
    Starting program: /home/leviathan6/leviathan6 

    Breakpoint 1, 0x080484d7 in main ()
    (gdb) disas
    Dump of assembler code for function main:
       0x080484d4 <+0>:	push   %ebp
       0x080484d5 <+1>:	mov    %esp,%ebp
    => 0x080484d7 <+3>:	and    $0xfffffff0,%esp
       0x080484da <+6>:	sub    $0x20,%esp
       0x080484dd <+9>:	movl   $0x1bd3,0x1c(%esp)
       0x080484e5 <+17>:	cmpl   $0x2,0x8(%ebp)
       0x080484e9 <+21>:	je     0x804850d <main+57>
       0x080484eb <+23>:	mov    0xc(%ebp),%eax
       0x080484ee <+26>:	mov    (%eax),%edx
       0x080484f0 <+28>:	mov    $0x8048620,%eax
       0x080484f5 <+33>:	mov    %edx,0x4(%esp)
       0x080484f9 <+37>:	mov    %eax,(%esp)
       0x080484fc <+40>:	call   0x80483a0 <printf@plt>
       0x08048501 <+45>:	movl   $0xffffffff,(%esp)
       0x08048508 <+52>:	call   0x80483f0 <exit@plt>
       0x0804850d <+57>:	mov    0xc(%ebp),%eax
       0x08048510 <+60>:	add    $0x4,%eax
       0x08048513 <+63>:	mov    (%eax),%eax
       0x08048515 <+65>:	mov    %eax,(%esp)
       0x08048518 <+68>:	call   0x8048410 <atoi@plt>
       0x0804851d <+73>:	cmp    0x1c(%esp),%eax
       0x08048521 <+77>:	jne    0x804853d <main+105>
       0x08048523 <+79>:	movl   $0x3ef,(%esp)
       0x0804852a <+86>:	call   0x80483b0 <seteuid@plt>
       0x0804852f <+91>:	movl   $0x804863a,(%esp)
       0x08048536 <+98>:	call   0x80483d0 <system@plt>
       0x0804853b <+103>:	jmp    0x8048549 <main+117>
       0x0804853d <+105>:	movl   $0x8048642,(%esp)
       0x08048544 <+112>:	call   0x80483c0 <puts@plt>
       0x08048549 <+117>:	leave  
       0x0804854a <+118>:	ret    
    End of assembler dump.
    (gdb) quit

Now we run the program with our new number.

    leviathan6@melinda:~$ ./leviathan6 7123
    $ cat /etc/leviathan_pass/leviathan7
    ahy7MaeBo9
    $ exit
    leviathan6@melinda:~$
    
# Level 7

User: leviathan7
Pass: ahy7MaeBo9

This level gives us a pleasant little congrats for getting here. Yay!