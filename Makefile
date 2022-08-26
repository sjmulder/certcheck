DESTDIR?=
PREFIX?=	/usr/local
MANPREFIX?=	${PREFIX}/man

VERSION=	0.1

CFLAGS+=	-Wall -Wextra
LDLIBS+=	-lssl -lcrypto

all: certcheck

clean:
	rm -f certcheck config.h *.o

install: all
	install -d ${DESTDIR}${PREFIX}/bin \
	           ${DESTDIR}${MANPREFIX}/man1
	install -m755 certcheck   ${DESTDIR}${PREFIX}/bin/
	install -m755 certcheck.1 ${DESTDIR}${MANPREFIX}/man1/

uninstall:
	rm -f ${DESTDIR}${PREFIX}/bin/certcheck \
	      ${DESTDIR}${MANPREFIX}/man1/certcheck.1

certcheck.o: config.h

config.h: Makefile
	echo '#define VERSION "${VERSION}"' >config.h

.POHNY: all clean install uninstall
