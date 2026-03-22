CC = cc
CFLAGS = -Wall -Wextra
LDLIBS = -lresolv

PROG = resquery

all: $(PROG)

resquery: resquery.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(PROG)

.PHONY: all clean
