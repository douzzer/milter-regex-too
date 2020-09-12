# $Id: Makefile.linux,v 1.3 2011/07/16 13:51:34 dhartmei Exp $
SHELL=/bin/bash

LIBS=  -lmaxminddb -lmilter -lpthread

all: milter-regex-too milter-regex-too.cat8

GITVERSION=$(shell git describe --always --dirty; git log -1 --date=iso --format='%cd %an <%aE>')

ifdef NO_GMIME
	GMIME_CFLAGS=
	GMIME_LDFLAGS=
else
	GMIME_CFLAGS=-DUSE_GMIME $(shell pkg-config --cflags gmime-3.0)
	GMIME_LDFLAGS=$(shell pkg-config --libs gmime-3.0)
endif

ifdef NO_PCRE2
	PCRE2_CFLAGS=
	PCRE2_LDFLAGS=
else
	PCRE2_CFLAGS=-DUSE_PCRE2 $(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig pkg-config --cflags libpcre2-posix)
	PCRE2_LDFLAGS=$(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig pkg-config --libs libpcre2-posix)
endif

override CFLAGS+=-std=gnu99 -O2 -g -MMD -DGITVERSION='"$(GITVERSION)"' -DGEOIP2 -DYYERROR_VERBOSE=1 -I/usr/local/include $(GMIME_CFLAGS) $(PCRE2_CFLAGS) -Wall -Werror -Wextra -Wformat=2 -Winit-self -Wunknown-pragmas -Wshadow -Wpointer-arith -Wbad-function-cast -Wcast-align -Wwrite-strings -Wstrict-prototypes -Wold-style-definition -Wmissing-declarations -Wmissing-format-attribute -Wpointer-arith -Wredundant-decls -Winline -Winvalid-pch -Wno-bad-function-cast

override LDFLAGS+=-L/usr/local/lib $(GMIME_LDFLAGS) $(PCRE2_LDFLAGS)

milter-regex-version.o: milter-regex.o eval.o geoip2.o strlcat.o strlcpy.o parse.tab.o

milter-regex-too: milter-regex-version.o milter-regex.o eval.o geoip2.o strlcat.o strlcpy.o parse.tab.o
	$(CC) $(LDFLAGS) -o $@ $+ $(LIBS)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

parse.tab.c parse.tab.h: parse.y
	bison -d parse.y

milter-regex-too.cat8: milter-regex-too.8
	nroff -Tascii -mandoc milter-regex-too.8 > milter-regex-too.cat8

clean:
	rm -f *.core milter-regex-too parse.tab.{c,h} *.o *.d *.cat8

#dependencies:
-include *.d
