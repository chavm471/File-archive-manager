CC = gcc

DEBUG = -g

CFLAGS = $(DEBUG) -Wall -Wextra -Wshadow -Wunreachable-code -Wredundant-decls \
		-Wmissing-declarations -Wold-style-definition \
		-Wmissing-prototypes -Wdeclaration-after-statement \
		-Wno-return-local-addr -Wunsafe-loop-optimizations \
		-Wuninitialized -Werror

PROG = viktar

all: $(PROG)

$(PROG): $(PROG).o
	$(CC) $(CFLAGS) -o $(PROG) $(PROG).o -lmd

$(PROG).o: $(PROG).c
	$(CC) $(CFLAGS) -c $(PROG).c

clean cls:
	rm -f $(PROG) *.o *~ \#*

tar:
	tar cvaf Lab3${LOGNAME}.tar.gz *.[c] [Mm]akefile
