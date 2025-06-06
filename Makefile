PROG = nbd-client
MAN = nbd-client.8
SRCS = hostcheck.c openssl_hostname_validation.c nbd-client.c ggate.c main.c
LDADD += -lm -lpthread
LDADD += -lcasper -lcap_net -lnv
LDADD += -lssl -lcrypto

# There needs to be a better way to do this.
DESTDIR = /usr/local
BINDIR = /sbin
MANDIR = /share/man/man
DEBUGDIR = /lib/debug

.include <bsd.prog.mk>
