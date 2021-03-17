all: shellcode

CC=gcc
CFLAGS= -g -z execstack -fno-stack-protector
shellcode: shellcode.o
	$(CC) $(CFLAGS) -o shellcode shellcode.o
shellcode.o:shellcode.c
	$(CC) $(CFLAGS) -c shellcode.c
	
clean:
	rm -f shellcode.o
