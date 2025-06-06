PROG = nbd-client
SRCS = hostcheck.c openssl_hostname_validation.c nbd-client.c ggate.c main.c
LDADD += -lm -lpthread
LDADD += -lcasper -lcap_net -lnv
LDADD += -lssl -lcrypto

DESTDIR = /usr/local
BINDIR = /sbin
MAN =

.include <bsd.prog.mk>
