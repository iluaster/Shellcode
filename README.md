# Shellcode

In the exploit code, you don't know the address of the function(e.g., printf, socket...) in advance, so you have to leverage system call to execute it.

> make
<pre>
GCC flags
  -z execstack: Since our shellcode is in the data segment,
                we must set it executable in the link-time.
  -fno-stack-protector: To remove the guard variable that detecting 
                        stack smash attack in the function epilogue.
</pre>
> objdump -D -M intel shellcode | less

The output :
<pre>
  00000000004004ed  <code>&lt;main&gt;</code> :

  4004ed:       55                      push   rbp
  4004ee:       48 89 e5                mov    rbp,rsp
  4004f1:       48 83 ec 10             sub    rsp,0x10
  4004f5:       48 c7 45 f8 60 10 60    mov    QWORD PTR [rbp-0x8],0x601060
  4004fc:       00 
  4004fd:       48 8b 55 f8             mov    rdx,QWORD PTR [rbp-0x8]
  400501:       b8 00 00 00 00          mov    eax,0x0
  400506:       ff d2                   call   rdx
  400508:       c9                      leave  
  400509:       c3                      ret    
  40050a:       66 0f 1f 44 00 00       nop    WORD PTR [rax+rax*1+0x0]
</pre>
It will call 0x601060 address in the main function.(in my computer, it's different in yours)

<pre>
0000000000601060  <code>&lt;shellcode&gt;</code> :
  601060:       48 b8 48 45 4c 4c 4f    movabs rax,0x94f4c4c4548
  601067:       09 00 00 
  60106a:       48 bb 00 00 00 00 00    movabs rbx,0x10000000000
  601071:       01 00 00 
  601074:       48 01 d8                add    rax,rbx
  601077:       50                      push   rax
  601078:       48 c7 c7 01 00 00 00    mov    rdi,0x1
  60107f:       48 89 e6                mov    rsi,rsp
  601082:       48 c7 c2 06 00 00 00    mov    rdx,0x6
  601089:       48 c7 c0 01 00 00 00    mov    rax,0x1
  601090:       0f 05                   syscall 
  601092:       48 c7 c0 3c 00 00 00    mov    rax,0x3c
  601099:       48 c7 c7 00 00 00 00    mov    rdi,0x0
  6010a0:       0f 05                   syscall 
</pre>
Here is the shellcode we insert.
<pre>
movabs rax,0x94f4c4c4548
movabs rbx,0x10000000000
add    rax,rbx
string 'HELLO\n' in little-endian format.
</pre>
<pre>
push   rax
push string to the top of stack.

mov    rdi,0x1 //stdout
mov    rsi,rsp //rsp is the top of stack.
mov    rdx,0x6 //the len of 'HELLO\n'
mov    rax,0x1 //the write system call
syscall  //call system call
mov    rax,0x3c //the exit system call
mov    rdi,0x0 //the exit status(return value)
</pre>
Linux system call table: https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md
