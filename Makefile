PROG = nbd-client
SRCS = hostcheck.c openssl_hostname_validation.c nbd-client.c ggate.c main.c
DEBUG_FLAGS = -g
CSTD = c11
CFLAGS = -O0 -pipe
LDADD += -lm -lpthread
LDADD += -lcasper -lcap_dns -lnv
LDADD += -lssl -lcrypto

DESTDIR = /usr/local
BINDIR = /sbin
MAN =

.include <bsd.prog.mk>
