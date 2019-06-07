CC=gcc
CFLAGS=-O0 -g -pipe
CFLAGS+=$(shell python3.8-config --cflags)
CFLAGS+=$(pkg-config libcrypto --cflags)
LDFLAGS+=$(shell python3.8-config --ldflags --embed)
LDFLAGS+=$(shell pkg-config libcrypto --libs)

objects=spython.o

all: spython

%.o: %.c
	$(CC) $(CFLAGS) -c $<

spython: spython.o
	$(CC) $(LDFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -rf *.o spython