# $Id: Makefile.linux,v 1.3 2011/07/16 13:51:34 dhartmei Exp $

LIBS=  -lmaxminddb -lmilter -lpthread

all: milter-regex milter-regex.cat8

GITVERSION=$(shell git describe --always --dirty; git log -1 --date=iso --format='%cd %an <%aE>')

override CFLAGS+=-std=gnu99 -O2 -MMD -DGITVERSION='"$(GITVERSION)"' -DGEOIP2 -DYYERROR_VERBOSE=1 -I/usr/local/include -Wall -Werror -Wextra -Wformat=2 -Winit-self -Wunknown-pragmas -Wshadow -Wpointer-arith -Wbad-function-cast -Wcast-align -Wwrite-strings -Wstrict-prototypes -Wold-style-definition -Wmissing-declarations -Wmissing-format-attribute -Wpointer-arith -Wredundant-decls -Winline -Winvalid-pch -Wno-bad-function-cast

override LDFLAGS+=-L/usr/local/lib

milter-regex: milter-regex.o eval.o geoip2.o strlcat.o strlcpy.o parse.tab.o
	$(CC) $(LDFLAGS) -o $@ $+ $(LIBS)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

parse.tab.c parse.tab.h: parse.y
	bison -d parse.y

milter-regex.cat8: milter-regex.8
	nroff -Tascii -mandoc milter-regex.8 > milter-regex.cat8

clean:
	rm -f *.core milter-regex parse.tab.{c,h} *.o *.d *.cat8

#dependencies:
-include *.d
