CC := cc
CFLAGS := -pthread -ggdb -D_GNU_SOURCE

motdsvr: main.c
	$(CC) $(CFLAGS) main.c -o motdsvr `pkg-config --cflags --libs libmicrohttpd`

clean:
	rm -f motdsvr
