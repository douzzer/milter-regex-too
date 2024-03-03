# $Id: Makefile.linux,v 1.3 2011/07/16 13:51:34 dhartmei Exp $
SHELL=/bin/bash

LIBS = -lmilter -lpthread

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
	PCRE2_CFLAGS=-DUSE_PCRE2 $(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig pkg-config --cflags libpcre2-posix libpcre2-8)
	PCRE2_LDFLAGS=$(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig pkg-config --libs libpcre2-posix libpcre2-8)
endif

ifdef NO_GEOIP
	GEOIP_CFLAGS=
	GEOIP_LDFLAGS=
	GEOIP_OBJS=
else
	GEOIP_CFLAGS=-DGEOIP2
	GEOIP_LDFLAGS=-lmaxminddb
	GEOIP_OBJS=geoip2.o
endif

ifdef LIBROKEN
	BROKEN_CFLAGS=-DUSE_LIBROKEN
	BROKEN_LDFLAGS=-lroken -lcrypt
else
	BROKEN_CFLAGS=
	BROKEN_LDFLAGS=
endif

override CFLAGS+=-std=gnu99 -O3 -g -MMD -DGITVERSION='"$(GITVERSION)"' $(GEOIP_CFLAGS) -DYYERROR_VERBOSE=1 -I/usr/local/include $(BROKEN_CFLAGS) $(GMIME_CFLAGS) $(PCRE2_CFLAGS) -Wall -Werror -Wextra -Wformat=2 -Winit-self -Wunknown-pragmas -Wshadow -Wpointer-arith -Wbad-function-cast -Wcast-align -Wwrite-strings -Wstrict-prototypes -Wold-style-definition -Wmissing-declarations -Wmissing-format-attribute -Wpointer-arith -Wredundant-decls -Winline -Winvalid-pch -Wno-bad-function-cast

override LDFLAGS+=-L/usr/local/lib $(GMIME_LDFLAGS) $(PCRE2_LDFLAGS) $(GEOIP_LDFLAGS) $(BROKEN_LDFLAGS)

sanitize: override CFLAGS+=-fsanitize=address -fsanitize=pointer-subtract -fsanitize=leak -fsanitize=undefined -fsanitize=float-cast-overflow -fsanitize=float-divide-by-zero -fsanitize=bounds-strict -fno-sanitize-recover=all
sanitize: override LDFLAGS+=-fsanitize=address -fsanitize=pointer-subtract -fsanitize=leak -fsanitize=undefined -fsanitize=float-cast-overflow -fsanitize=float-divide-by-zero -fsanitize=bounds-strict -fno-sanitize-recover=all
sanitize: all

# glibc 2.38 adds strlcat/strlcpy -- test empirically.
HAVE_STRLCPY := $(shell if printf '\
        #include <stdlib.h>\n\
        #include <string.h>\n\
        #include <stdio.h>\n\
        int main(int argc, char **argv) {\n\
	    static const char s[] = "foo";\n\
	    char c[10];\n\
            (void)argc; (void)argv;\n\
	    strlcpy(c, s, sizeof c);\n\
	    strlcat(c, s, sizeof c);\n\
	    puts(c);\n\
	    return 0;\n\
        }' | $(CC) $(CFLAGS) $(LDFLAGS) -x c - -o /dev/null -MF /dev/null >/dev/null 2>&1;\
	then echo 1; else echo 0; fi)

ifeq "$(HAVE_STRLCPY)" "0"
    EXTRA_OBJS := strlcat.o strlcpy.o
    override CFLAGS += -DNEED_BUNDLED_STRL
endif

milter-regex-version.o: milter-regex.o eval.o $(GEOIP_OBJS) parse.tab.o $(EXTRA_OBJS)

milter-regex-too: milter-regex-version.o milter-regex.o eval.o $(GEOIP_OBJS) parse.tab.o $(EXTRA_OBJS)
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
