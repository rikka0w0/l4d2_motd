CC := cc
CFLAGS := -pthread -ggdb -D_GNU_SOURCE -g
MAKE := make

all: main.c
	+$(MAKE) -C l4d2query l4d2query
	$(CC) $(CFLAGS) main.c l4d2query/l4d2query.o -o motdsvr `pkg-config --cflags --libs libmicrohttpd`

clean:
	+$(MAKE) -C l4d2query clean
	rm -f motdsvr
