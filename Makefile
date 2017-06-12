
CC = gcc
CFLAGS = -I.

bin/packetdump: src/*.c lz4/*.c
	$(CC) $(CFLAGS) -o $@ $^
