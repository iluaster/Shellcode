all: shellcode

CC=gcc
CFLAGS= -g -z execstack
speed_test: shellcode.o
	$(CC) $(CFLAGS) -o shellcode shellcode.o
speed_test.o:speed_test.c
	$(CC) $(CFLAGS) -c shellcode.c
	
clean:
	rm -f shellcode.o
