/*
 * Copyright (c) 2016-2025 Ryan Moeller
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/bio.h>
#include <sys/capsicum.h>
#include <sys/endian.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/syslimits.h>
#include <assert.h>
#include <capsicum_helpers.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <libcasper.h>
#include <casper/cap_net.h>

#include <geom/gate/g_gate.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include "openssl_hostname_validation.h"

#include "check.h"
#include "ggate.h"
#include "ggio.h"
#include "nbd-client.h"
#include "nbd-protocol.h"

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#define SSL_CTX_load_verify_file(ctx, file) \
    SSL_CTX_load_verify_locations((ctx), (file), NULL)
#endif

#define DEFAULT_BUFFER_SIZE (1536 * 1024)
#define DEFAULT_SECTOR_SIZE 512
#define DEFAULT_GGATE_FLAGS 0

/*
 * How many concurrent commands will we allow?  Sizes the freelist.
 * XXX: Arbitrary compile-time constant could be tunable or adaptive.
 */
#ifndef MAX_QUEUE_DEPTH
#define MAX_QUEUE_DEPTH 128
#endif

/*
 * How long will we sleep between reconnect retries?  In seconds.
 * XXX: Arbitrary compile-time constant could be tunable or adaptive.
 */
#ifndef RECONNECT_RETRY_DELAY
#define RECONNECT_RETRY_DELAY 2 /* seconds */
#endif

static void
usage(void)
{
	fprintf(stderr, "usage: %s "
	    "[-fl] [-c num] [-n export] [-r rcvbuf] [-s sndbuf] "
	    "[[-A cacert] -C cert -K key] [-S sectorsize] host [port]\n",
	    getprogname());
}

static int
list_callback(void *ctx __unused, char *name, char *description)
{
	if (name == NULL)
		printf("[default export]");
	else {
		printf("%s", name);
		free(name);
	}
	if (description == NULL)
		printf("\n");
	else {
		printf("\t%s\n", description);
		free(description);
	}
	/* TODO: verbosity control, more export info */
	return (SUCCESS);
}

static _Atomic(bool) disconnect;

static void
signal_handler(int sig __unused)
{
	atomic_store(&disconnect, true);
	/* TODO: signal waiting threads? */
}

static int
setup_signals(void)
{
	const int signals[] = { SIGHUP, SIGINT, SIGTERM };

	for (int i = 0; i < nitems(signals); i++)
		if (signal(signals[i], signal_handler) == SIG_ERR)
			return (FAILURE);
	return (SUCCESS);
}

/*
 * Maximum block I/O access size.
 *
 * We use it to size the ggio buffer allocations.
 */
static unsigned long maxphys;

/*
 * Unused initialized ggio structures.
 *
 * The freelist is populated with initialized ggio structures during setup.
 * We take a ggio from the freelist and wait for ggate to issue IO with it, then
 * we put it in the connection's inflight queue.  After completion the ggio is
 * returned to the freelist.
 */
static struct ggioq ggio_freelist;

/*
 * Shared ggate context.  All connections use this in the sender and receiver
 * threads to start and finish IO requests.
 */
static ggate_context_t ggate;

/*
 * When flushing, this lock is held exclusively until all pending writes/deletes
 * have completed.
 */
static pthread_rwlock_t flush_lock;

/*
 * Not protected by a lock, this is set when we need write/delete completion to
 * signal the flush_cond for a connection.
 */
static _Atomic(bool) flushing;

/*
 * Not protected by a lock, this is set when we are waiting for a flush and an
 * inflight IO request results in an error.
 */
static _Atomic(int) flush_error;

enum connection_state {
	CONNECTED,
	SOFT_DISCONNECTING,
	HARD_DISCONNECTING,
	DISCONNECTED,
};

struct connection {
	nbd_client_t nbd;
	cap_channel_t *capnet;
	pthread_t sender;
	pthread_t receiver;

	/*
	 * The fields above are read-only during the transmission phase.  Align
	 * the atomic below to a different cache line so it does not evict the
	 * rest of the fields when accessed.
	 */
	_Atomic(enum connection_state) state __aligned(CACHE_LINE_SIZE);

	/*
	 * IO commands sent to the server and waiting for a reply.
	 *
	 * The sender threads for a connection take a ggio from the freelist and
	 * wait for ggate to start IO with it.  When ggate issues IO the sender
	 * thread puts the ggio in the inflight queue before sending it to the
	 * server.  When the receiver thread receives the reply to complete an
	 * IO it takes the ggio from the inflight queue and passes it back
	 * through ggate before returning it to the freelist.
	 */
	struct ggioq inflight;

	/*
	 * Signaled when an IO command blocking flush is completed.  Locked by
	 * the inflight queue lock.
	 */
	pthread_cond_t flush_cond;

	/*
	 * Signaled when the receiver thread has shutdown the connection.
	 * Locked by the inflight queue lock.
	 */
	pthread_cond_t shutdown_cond;

	/*
	 * Signaled when the sender has reestablished the connection. Locked by
	 * the inflight queue lock.
	 */
	pthread_cond_t reconnect_cond;
};

/*
 * Degrade connection state if possible, locklessly.
 */
static inline void
connection_degrade(struct connection *conn, enum connection_state state)
{
	enum connection_state old;

	old = CONNECTED;
	if (atomic_compare_exchange_strong(&conn->state, &old, state))
		return;
	old = SOFT_DISCONNECTING;
	atomic_compare_exchange_strong(&conn->state, &old, state);
}

static inline const char *
bio_cmd_string(uint16_t cmd)
{
	switch (cmd) {
#define CASE_MESSAGE(c) case c: return (#c)
	CASE_MESSAGE(BIO_READ);
	CASE_MESSAGE(BIO_WRITE);
	CASE_MESSAGE(BIO_DELETE);
	CASE_MESSAGE(BIO_GETATTR);
	CASE_MESSAGE(BIO_FLUSH);
	CASE_MESSAGE(BIO_CMD0);
	CASE_MESSAGE(BIO_CMD1);
	CASE_MESSAGE(BIO_CMD2);
#ifdef BIO_ZONE
	CASE_MESSAGE(BIO_ZONE);
#endif
#undef CASE_MESSAGE
	default: return ("[unknown]");
	}
}

static inline struct ggio *
ggio_start(void)
{
	struct ggio *ggio;

	ggio = ggioq_dequeue(&ggio_freelist, &disconnect);
	if (ggio == NULL)
		return (NULL);
	ggio->io.gctl_length = maxphys;
	ggio->io.gctl_error = SUCCESS;
	if (ggate_context_ioctl(ggate, G_GATE_CMD_START, &ggio->io)
	    == FAILURE) {
		syslog(LOG_ERR, "%s: ggate_context_ioctl failed", __func__);
		ggioq_enqueue(&ggio_freelist, ggio);
		return (NULL);
	}
	return (ggio);
}

static inline int
ggio_done(struct ggio *ggio, int error)
{
	ggio->io.gctl_error = error;
	if (ggate_context_ioctl(ggate, G_GATE_CMD_DONE, &ggio->io)
	    == FAILURE) {
		syslog(LOG_ERR, "%s: ggate_context_ioctl failed", __func__);
		ggioq_enqueue(&ggio_freelist, ggio);
		return (FAILURE);
	}
	ggioq_enqueue(&ggio_freelist, ggio);
	return (SUCCESS);
}

static struct connection *connections;
static unsigned nconns;

static int
flush_wait(void)
{
	struct connection *conn;
	struct ggio *ggio;
	int error;

	atomic_store(&flushing, true);
	for (int i = 0; i < nconns; i++) {
		conn = &connections[i];
		pthread_mutex_lock(&conn->inflight.lock);
restart:
		TAILQ_FOREACH(ggio, &conn->inflight.head, link) {
			switch (ggio->io.gctl_cmd) {
			case BIO_DELETE:
			case BIO_WRITE:
				pthread_cond_wait(&conn->flush_cond,
				    &conn->inflight.lock);
				/* Have to start over, the lock was dropped. */
				goto restart;
			}
		}
		pthread_mutex_unlock(&conn->inflight.lock);
	}
	error = atomic_exchange(&flush_error, SUCCESS);
	atomic_store(&flushing, false);
	return (error);
}

static int
connection_ggio_done(struct connection *conn, struct ggio *ggio, int error)
{
	int cmd = ggio->io.gctl_cmd;
	int expected, result;

	result = ggio_done(ggio, error);
	if (nconns > 1 && atomic_load(&flushing)) {
		switch (cmd) {
		case BIO_WRITE:
		case BIO_DELETE:
			/*
			 * We're blocking a flush operation.  If there was an
			 * error, signal it to the flush.
			 */
			if (result != SUCCESS)
				error = EIO;
			if (error != SUCCESS) {
				expected = SUCCESS;
				atomic_compare_exchange_strong(&flush_error,
				    &expected, error);
			}
			pthread_cond_signal(&conn->flush_cond);
		}
	}
	return (result);
}

static inline bool
connection_sending(struct connection *conn)
{
	return (atomic_load(&conn->state) == CONNECTED &&
	    !atomic_load(&disconnect));
}

static const char *name, *host, *port;

static void *
sender(void *arg)
{
	struct connection *conn = arg;
	struct ggio *ggio;
	int error, result;

restart:
	while (connection_sending(conn)) {
		ggio = ggio_start();
		if (ggio == NULL) {
			if (!atomic_load(&disconnect))
				connection_degrade(conn, HARD_DISCONNECTING);
			break;
		}
		/* ???: is this really how this works? */
		if (ggio->io.gctl_error != SUCCESS) {
			connection_ggio_done(conn, ggio, ggio->io.gctl_error);
			break;
		}
		/*
		 * Wait for inflight IO to complete before issuing flush when
		 * multiple connections are in use.
		 */
		if (nconns > 1) {
			if (ggio->io.gctl_cmd == BIO_FLUSH) {
				pthread_rwlock_wrlock(&flush_lock);
				error = flush_wait();
				if (error != 0) {
					/*
					 * Fail fast and let the application
					 * decide how to handle it.
					 */
					ggio_done(ggio, error);
					pthread_rwlock_unlock(&flush_lock);
					continue;
				}
			} else
				pthread_rwlock_rdlock(&flush_lock);
		}
		/* Enqueue to inflight before sending to avoid racing. */
		ggioq_enqueue(&conn->inflight, ggio);
		/* For multi-connection flush we unlock after sending. */
		if (nconns > 1 && ggio->io.gctl_cmd != BIO_FLUSH)
			pthread_rwlock_unlock(&flush_lock);
		error = EIO;
		switch (ggio->io.gctl_cmd) {
		case BIO_READ:
			result = nbd_client_send_read(conn->nbd,
			    ggio->io.gctl_seq,
			    ggio->io.gctl_offset,
			    ggio->io.gctl_length);
			break;
		case BIO_WRITE:
			result = nbd_client_send_write(conn->nbd,
			    ggio->io.gctl_seq,
			    ggio->io.gctl_offset,
			    ggio->io.gctl_length,
			    ggio->io.gctl_length,
			    ggio->io.gctl_data);
			break;
		case BIO_DELETE:
			result = nbd_client_send_trim(conn->nbd,
			    ggio->io.gctl_seq,
			    ggio->io.gctl_offset,
			    ggio->io.gctl_length);
			if (result == EOPNOTSUPP)
				error = EOPNOTSUPP;
			break;
		case BIO_FLUSH:
			result = nbd_client_send_flush(conn->nbd,
			    ggio->io.gctl_seq);
			if (nconns > 1)
				pthread_rwlock_unlock(&flush_lock);
			if (result == EOPNOTSUPP)
				error = EOPNOTSUPP;
			break;
		case BIO_GETATTR:
			/* TODO in kernel */
		default:
			syslog(LOG_NOTICE, "%s: unsupported operation: %s (%d)",
			    __func__, bio_cmd_string(ggio->io.gctl_cmd),
			    ggio->io.gctl_cmd);
			result = FAILURE;
			error = EOPNOTSUPP;
			break;
		}
		if (result != SUCCESS) {
			ggioq_remove(&conn->inflight, ggio);
			connection_ggio_done(conn, ggio, error);
			connection_degrade(conn, HARD_DISCONNECTING);
			break;
		}
	}
	/* Initiate a soft disconnect, unless we are already in worse state. */
	connection_degrade(conn, SOFT_DISCONNECTING);
	if (atomic_load(&conn->state) == SOFT_DISCONNECTING &&
	    nbd_client_send_disconnect(conn->nbd) == FAILURE)
		connection_degrade(conn, HARD_DISCONNECTING);
	/* Wait for the receiver thread to drain the inflight queue. */
	pthread_mutex_lock(&conn->inflight.lock);
	pthread_cond_wait(&conn->shutdown_cond, &conn->inflight.lock);
	pthread_mutex_unlock(&conn->inflight.lock);
	while (!atomic_load(&disconnect)) {
		struct addrinfo hints, *ai, *ai1;

		/* Try to reconnect. */
		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_CANONNAME;
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		result = cap_getaddrinfo(conn->capnet, host, port, &hints, &ai);
		if (result != SUCCESS) {
			syslog(LOG_NOTICE,
			    "%s: failed to lookup address (%s:%s): %s "
			    "(retrying in %u seconds)", __func__, host, port,
			    gai_strerror(result), RECONNECT_RETRY_DELAY);
			sleep(RECONNECT_RETRY_DELAY);
			continue;
		}
		nbd_client_close(conn->nbd);
		ai1 = nbd_client_connect(conn->nbd, conn->capnet, host, ai);
		freeaddrinfo(ai);
		if (ai1 == NULL) {
			syslog(LOG_NOTICE,
			    "%s: failed to reconnect (retrying in %u seconds)",
			    __func__, RECONNECT_RETRY_DELAY);
			sleep(RECONNECT_RETRY_DELAY);
			continue;
		}
		if (nbd_client_rights_limit(conn->nbd) == FAILURE) {
			syslog(LOG_ERR, "%s: failed to limit client rights",
			    __func__);
			nbd_client_abort(conn->nbd);
			nbd_client_shutdown(conn->nbd);
			break;
		}
		if (nbd_client_negotiate(conn->nbd, name) == FAILURE) {
			syslog(LOG_ERR, "%s: failed to negotiate options",
			    __func__);
			nbd_client_send_disconnect(conn->nbd);
			nbd_client_shutdown(conn->nbd);
			break;
		}
		atomic_store(&conn->state, CONNECTED);
		/* Let the receiver thread know we are reconnected. */
		pthread_cond_signal(&conn->reconnect_cond);
		goto restart;
	}
	/* Resume the receiver thread if waiting so it can exit. */
	pthread_cond_signal(&conn->reconnect_cond);
	return (NULL);
}

static inline bool
connection_receiving(struct connection *conn)
{
	switch (atomic_load(&conn->state)) {
	case CONNECTED:
		return (true);
	case SOFT_DISCONNECTING:
		return (!ggioq_empty(&conn->inflight));
	default:
		return (false);
	}
}

static inline int
nbd_error_to_errno(int error)
{
	switch (error) {
	case NBD_EOVERFLOW: return (EOVERFLOW);
	case NBD_ESHUTDOWN: return (ESHUTDOWN);
	default: return (error);
	}
}

static void *
receiver(void *arg)
{
	struct connection *conn = arg;
	struct ggio *ggio;
	uint64_t handle;
	int result;

restart:
	while (connection_receiving(conn)) {
		/* TODO: how to interrupt this? */
		result = nbd_client_recv_reply_header(conn->nbd, &handle);
		if (result == FAILURE) {
			syslog(LOG_ERR, "%s: failed to receive reply header",
			    __func__);
			break;
		}
		/* TODO: structured replies, pass errors through to ggate */
		ggio = ggioq_find(&conn->inflight, handle);
		if (ggio == NULL) {
			syslog(LOG_NOTICE, "%s: unexpected reply: %lu",
			    __func__, handle);
			break;
		}
		/* XXX: have seen EINVAL from server advertising TRIM support */
		if (result == NBD_EINVAL && ggio->io.gctl_cmd == BIO_DELETE) {
			nbd_client_disable_trim(conn->nbd);
			connection_ggio_done(conn, ggio, EOPNOTSUPP);
			continue;
		}
		if (result != SUCCESS) {
			/* TODO: does every error require disconnection? */
			connection_degrade(conn, SOFT_DISCONNECTING);
			connection_ggio_done(conn, ggio,
			    nbd_error_to_errno(result));
			continue;
		}
		if (ggio->io.gctl_cmd == BIO_READ) {
			/* TODO: how to interrupt this? */
			result = nbd_client_recv_reply_data(conn->nbd,
			    ggio->io.gctl_length,
			    ggio->io.gctl_length,
			    ggio->io.gctl_data);
			if (result != SUCCESS) {
				syslog(LOG_ERR,
				    "%s: failed to receive reply data",
				    __func__);
				connection_ggio_done(conn, ggio, EIO);
				break;
			}
		}
		result = connection_ggio_done(conn, ggio, SUCCESS);
		if (result != SUCCESS)
			connection_degrade(conn, SOFT_DISCONNECTING);
	}
	/* We are done with the socket. */
	connection_degrade(conn, HARD_DISCONNECTING);
	nbd_client_set_disconnect(conn->nbd, true);
	nbd_client_shutdown(conn->nbd);
	pthread_mutex_lock(&conn->inflight.lock);
	/* Remaining IO must be handled by another connection. */
	while ((ggio = ggioq_takefirst(&conn->inflight)) != NULL)
		connection_ggio_done(conn, ggio, EAGAIN);
	pthread_mutex_unlock(&conn->inflight.lock);
	atomic_store(&conn->state, DISCONNECTED);
	/* Let the sender thread know we are disconnected. */
	pthread_cond_signal(&conn->shutdown_cond);
	if (!atomic_load(&disconnect)) {
		/* Wait for the sender thread to reconnect. */
		pthread_mutex_lock(&conn->inflight.lock);
		pthread_cond_wait(&conn->reconnect_cond, &conn->inflight.lock);
		pthread_mutex_unlock(&conn->inflight.lock);
		if (atomic_load(&conn->state) != DISCONNECTED)
			goto restart;
	}
	return (NULL);
}

/* See http://archives.seul.org/libevent/users/Jan-2013/msg00039.html */
static int
cert_verify_callback(X509_STORE_CTX *x509_ctx, void *arg)
{
	const char *host = arg;
	X509 *server_cert;

	if (X509_verify_cert(x509_ctx) != 1)
		return (0);
	server_cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	if (validate_hostname(host, server_cert) != MatchFound) {
		syslog(LOG_ERR, "%s: failed to validate server hostname",
		    __func__);
		return (0);
	}
	return (1);
}

static SSL_CTX *
setup_tls(char const *cacertfile, char const *certfile, char const *keyfile)
{
	SSL_CTX *ssl_ctx;

	ssl_ctx = SSL_CTX_new(TLS_client_method());
	if (ssl_ctx == NULL) {
		ERR_print_errors_fp(stderr);
		syslog(LOG_ERR, "%s: failed to create TLS client",
		    __func__);
		return (NULL);
	}
	if (cacertfile != NULL &&
	    SSL_CTX_load_verify_file(ssl_ctx, cacertfile) != 1) {
		ERR_print_errors_fp(stderr);
		syslog(LOG_ERR, "%s: failed to load CA certificate %s",
		    __func__, cacertfile);
		return (NULL);
	}
	if (SSL_CTX_use_certificate_chain_file(ssl_ctx, certfile) != 1) {
		ERR_print_errors_fp(stderr);
		syslog(LOG_ERR,
		    "%s: failed to use certificate chain %s",
		    __func__, certfile);
		return (NULL);
	}
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, keyfile,
	    SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		syslog(LOG_ERR, "%s: failed to use private key %s",
		    __func__, keyfile);
		return (NULL);
	}
	if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
		ERR_print_errors_fp(stderr);
		syslog(LOG_ERR, "%s: private key %s failed check",
		    __func__, keyfile);
		return (NULL);
	}
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_cert_verify_callback(ssl_ctx, cert_verify_callback,
	    __DECONST(void *, host));
	SSL_CTX_set_options(ssl_ctx, SSL_OP_ENABLE_KTLS);
	SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_VERSION);
	return (ssl_ctx);
}

static cap_channel_t *
casper_enter_net(void)
{
	cap_channel_t *capcas, *capnet;
	cap_net_limit_t *limit;

	fclose(stdin);
	capcas = cap_init();
	if (capcas == NULL) {
		syslog(LOG_ERR, "%s: failed to initialize Casper", __func__);
		return (NULL);
	}
	caph_cache_catpages();
	if (caph_enter_casper() < 0) {
		syslog(LOG_ERR, "%s: failed to enter capability mode",
		    __func__);
		cap_close(capcas);
		return (NULL);
	}
	capnet = cap_service_open(capcas, "system.net");
	cap_close(capcas);
	if (capnet == NULL) {
		syslog(LOG_ERR, "%s: failed to open system.net service",
		    __func__);
		return (NULL);
	}
	limit = cap_net_limit_init(capnet,
	    CAPNET_NAME2ADDR | CAPNET_CONNECTDNS);
	if (limit == NULL) {
		syslog(LOG_ERR, "%s: failed to create limits", __func__);
		cap_close(capnet);
		return (NULL);
	}
	cap_net_limit_name2addr(limit, host, port);
	if (cap_net_limit(limit) < 0) {
		syslog(LOG_ERR, "%s: failed to apply limits", __func__);
		cap_close(capnet);
		return (NULL);
	}
	return (capnet);
}

static unsigned sndbuf;
static unsigned rcvbuf;

static int
list_exports(SSL_CTX *ssl_ctx)
{
	nbd_client_t nbd;
	cap_channel_t *capnet;
	struct addrinfo hints, *ai, *ai1;
	int result, retval;

	retval = EXIT_FAILURE;
	nbd = nbd_client_alloc();
	assert(nbd != NULL);
	nbd_client_init(nbd, ssl_ctx, sndbuf, rcvbuf);
	capnet = casper_enter_net();
	if (capnet == NULL)
		goto close;
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	result = cap_getaddrinfo(capnet, host, port, &hints, &ai);
	if (result != SUCCESS) {
		syslog(LOG_ERR, "%s: failed to lookup addres (%s:%s): %s",
		    __func__, host, port, gai_strerror(result));
		cap_close(capnet);
		goto close;
	}
	ai1 = nbd_client_connect(nbd, capnet, host, ai);
	cap_close(capnet);
	freeaddrinfo(ai);
	if (ai1 == NULL)
		goto close;
	if (nbd_client_rights_limit(nbd) == SUCCESS)
		retval = nbd_client_list(nbd, list_callback, NULL);
	nbd_client_abort(nbd);
	nbd_client_shutdown(nbd);
close:
	nbd_client_close(nbd);
	SSL_CTX_free(ssl_ctx);
	if (retval == EXIT_FAILURE)
		syslog(LOG_ERR, "%s: failed to connect to server (%s:%s)",
		    __func__, host, port);
	return (retval);
}

int
main(int argc, char *argv[])
{
	char ident[G_GATE_INFOSIZE];
	struct connection *conn;
	struct ggio *freelist;
	const char *cacertfile, *certfile, *keyfile;
	SSL_CTX *ssl_ctx;
	cap_channel_t *capnet;
	struct addrinfo hints, *ai, *ai1;
	size_t page_size;
	uint64_t size;
	uint32_t minbs, prefbs, sector_size;
	bool daemonize, list;
	int result, retval, unit;

	retval = EXIT_FAILURE;
	name = "";
	cacertfile = certfile = keyfile = NULL;
	ssl_ctx = NULL;
	daemonize = true;
	list = false;
	freelist = NULL;
	connections = NULL;
	nconns = 1;
	sndbuf = DEFAULT_BUFFER_SIZE;
	rcvbuf = DEFAULT_BUFFER_SIZE;
	sector_size = 0;
	page_size = getpagesize();

	/* TODO: check for strtoul() parse errors */
	while ((result = getopt(argc, argv, "c:fln:r:s:A:C:K:S:")) != -1) {
		switch (result) {
		case 'c':
			nconns = strtoul(optarg, NULL, 10);
			break;
		case 'f':
			daemonize = false;
			break;
		case 'l':
			list = true;
			break;
		case 'n':
			name = optarg;
			break;
		case 'r':
			rcvbuf = strtoul(optarg, NULL, 10);
			break;
		case 's':
			sndbuf = strtoul(optarg, NULL, 10);
			break;
		case 'A':
			cacertfile = optarg;
			break;
		case 'C':
			certfile = optarg;
			break;
		case 'K':
			keyfile = optarg;
			break;
		case 'S':
			sector_size = strtoul(optarg, NULL, 10);
			break;
		case '?':
		default:
			usage();
			return (EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1 || argc > 2) {
		usage();
		return (EXIT_FAILURE);
	}
	if (nconns < 1) {
		fprintf(stderr, "invalid number of connections\n\n");
		usage();
		return (EXIT_FAILURE);
	}
	if (sndbuf < page_size) {
		fprintf(stderr, "requested send buffer size too small\n\n");
		usage();
		return (EXIT_FAILURE);
	}
	if (rcvbuf < page_size) {
		fprintf(stderr, "requested receive buffer size too small\n\n");
		usage();
		return (EXIT_FAILURE);
	}
	if (sector_size < 0) {
		fprintf(stderr, "invalid sector size\n\n");
		usage();
		return (EXIT_FAILURE);
	}
	if (cacertfile != NULL && certfile == NULL) {
		usage();
		return (EXIT_FAILURE);
	}
	if (certfile != NULL && keyfile == NULL) {
		usage();
		return (EXIT_FAILURE);
	}
	if (keyfile != NULL && certfile == NULL) {
		usage();
		return (EXIT_FAILURE);
	}

	host = argv[0];
	if (argc == 2)
		port = argv[1];
	else
		port = NBD_DEFAULT_PORT;

	snprintf(ident, sizeof(ident), "%s (%s%s%s%s%s)", getprogname(), host,
	    strcmp(port, NBD_DEFAULT_PORT) == 0 ? "" : ":",
	    strcmp(port, NBD_DEFAULT_PORT) == 0 ? "" : port,
	    name[0] == '\0' ? "" : "/", name);

	/*
	 * LOG_NDELAY makes sure the connection to syslogd is opened before
	 * entering capability mode.
	 */
	if (isatty(fileno(stderr)))
		openlog(NULL, LOG_NDELAY | LOG_PERROR, LOG_USER);
	else
		openlog(ident, LOG_NDELAY | LOG_CONS | LOG_PID, LOG_DAEMON);

	if (certfile != NULL) {
		ssl_ctx = setup_tls(cacertfile, certfile, keyfile);
		if (ssl_ctx == NULL)
			return (EXIT_FAILURE);
	}

	if (list)
		return (list_exports(ssl_ctx));

	if (ggate_load_module() == FAILURE)
		goto cleanup1;

	ggate = ggate_context_alloc();
	if (ggate == NULL)
		goto cleanup1;

	{
		const int maxphys_mib[] = { CTL_KERN, KERN_MAXPHYS };
		size_t maxphys_size = sizeof(maxphys);

		if (sysctl(maxphys_mib, nitems(maxphys_mib), &maxphys,
		    &maxphys_size, NULL, 0) != 0) {
			syslog(LOG_ERR, "%s: failed to get kern.maxphys: %m",
			    __func__);
			goto cleanup1;
		}
		assert(maxphys_size == sizeof(maxphys));
	}

	connections = calloc(nconns, sizeof(*connections));
	assert(connections != NULL);
	for (int i = 0; i < nconns; i++) {
		conn = &connections[i];
		conn->nbd = nbd_client_alloc();
		assert(conn->nbd != NULL);
		nbd_client_init(conn->nbd, ssl_ctx, sndbuf, rcvbuf);
		ggioq_init(&conn->inflight);
		if (nconns > 1)
			pthread_cond_init(&conn->flush_cond, NULL);
		pthread_cond_init(&conn->shutdown_cond, NULL);
		pthread_cond_init(&conn->reconnect_cond, NULL);
	}
	pthread_rwlock_init(&flush_lock, NULL);

	/* TODO: Can this be moved further down so early errors get caught? */
	if (daemonize && daemon(0, 1) == FAILURE) {
		syslog(LOG_ERR, "%s: failed to daemonize: %m", __func__);
		goto cleanup;
	}

	ggate_context_init(ggate);
	if (ggate_context_open(ggate) == FAILURE) {
		syslog(LOG_ERR, "%s: cannot open ggate context", __func__);
		goto cleanup;
	}

	/*
	 * Set up Casper, enter capability mode, and get a handle to the
	 * system.net service limited to the given host/port.  Limit the rights
	 * on the ggate ctl descriptor now.  The nbd socket rights are limited
	 * after the connections are established, as we don't have the sockets
	 * until then.
	 */
	capnet = casper_enter_net();
	if (capnet == NULL || ggate_context_rights_limit(ggate) == FAILURE)
		goto close;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	result = cap_getaddrinfo(capnet, host, port, &hints, &ai);
	if (result != SUCCESS) {
		syslog(LOG_ERR, "%s: failed to lookup addres (%s:%s): %s",
		    __func__, host, port, gai_strerror(result));
		cap_close(capnet);
		goto close;
	}
	ai1 = ai;
	for (int i = 0; i < nconns; i++) {
		conn = &connections[i];
		conn->capnet = cap_clone(capnet);
		assert(conn->capnet != NULL);
		ai1 = nbd_client_connect(conn->nbd, capnet, host, ai1);
		if (ai1 == NULL) {
			for (i--; i >= 0; i--) {
				conn = &connections[i];
				nbd_client_abort(conn->nbd);
				nbd_client_shutdown(conn->nbd);
			}
			result = FAILURE;
		} else
			result = nbd_client_rights_limit(conn->nbd);
		if (result == FAILURE)
			break;
	}
	freeaddrinfo(ai);
	cap_close(capnet);
	if (result == FAILURE) {
		syslog(LOG_ERR, "%s: failed to connect to server (%s:%s)",
		    __func__, host, port);
		goto close;
	}

	for (int i = 0; i < nconns; i++) {
		conn = &connections[i];
		if (nbd_client_negotiate(conn->nbd, name) == FAILURE) {
			syslog(LOG_ERR, "%s: failed to negotiate options",
			    __func__);
			for (int j = 0; j < i; j++) {
				conn = &connections[j];
				nbd_client_send_disconnect(conn->nbd);
				nbd_client_shutdown(conn->nbd);
			}
			for (; i < nconns; i++) {
				conn = &connections[i];
				nbd_client_abort(conn->nbd);
				nbd_client_shutdown(conn->nbd);
			}
			goto close;
		}
	}

	size = nbd_client_get_size(connections[0].nbd);
	nbd_client_get_block_sizes(connections[0].nbd, &minbs, &prefbs, NULL);
	/* NBD recommends clients enforce minimum 512 bytes for sector size. */
	minbs = MAX(minbs, DEFAULT_SECTOR_SIZE);
	if (sector_size == 0)
		sector_size = MAX(minbs, prefbs);
	else
		sector_size = MAX(minbs, sector_size);

	if (ggate_context_create_device(ggate, ident, size, sector_size,
	    DEFAULT_GGATE_FLAGS) == FAILURE) {
		syslog(LOG_ERR, "%s: failed to create ggate device", __func__);
		goto disconnect;
	}

	unit = ggate_context_get_unit(ggate);
	printf("%s%d\n", G_GATE_PROVIDER_NAME, unit);
	fflush(stdout);

	if (daemonize) {
		/*
		 * Now that we've printed the device name we can close
		 * stdout/stderr to complete the daemonization.
		 */
		fclose(stdout);
		fclose(stderr);
	}

	if (setup_signals() == FAILURE) {
		syslog(LOG_ERR, "%s: failed to setup signals", __func__);
		goto destroy;
	}

	freelist = calloc(MAX_QUEUE_DEPTH, sizeof(*freelist));
	assert(freelist != NULL);
	ggioq_init(&ggio_freelist);
	for (int i = 0; i < MAX_QUEUE_DEPTH; i++) {
		struct ggio *ggio = &freelist[i];

		ggio->io.gctl_version = G_GATE_VERSION;
		ggio->io.gctl_unit = unit;
		/* TODO: This should be done on demand, reaped, etc. */
		ggio->io.gctl_data = aligned_alloc(page_size, maxphys);
		assert(ggio->io.gctl_data != NULL);
		TAILQ_INSERT_TAIL(&ggio_freelist.head, &freelist[i], link);
	}

	for (int i = 0; i < nconns; i++) {
		conn = &connections[i];
		result = pthread_create(&conn->receiver, NULL, receiver, conn);
		if (result != SUCCESS)
			break;
		result = pthread_create(&conn->sender, NULL, sender, conn);
		if (result != SUCCESS)
			break;
	}
	if (result == SUCCESS)
		retval = EXIT_SUCCESS;
	else
		atomic_store(&disconnect, true);

	for (int i = 0; i < nconns; i++) {
		struct ggioq *ggioq;
		struct ggio *ggio;

		conn = &connections[i];
		if (result != SUCCESS) {
			connection_degrade(conn, SOFT_DISCONNECTING);
			pthread_cond_signal(&conn->inflight.cond);
		}
		pthread_join(conn->sender, NULL);
		pthread_join(conn->receiver, NULL);
		ggioq = &conn->inflight;
		while ((ggio = TAILQ_FIRST(&ggioq->head)) != NULL) {
			ggate_context_cancel(ggate, ggio->io.gctl_seq);
			TAILQ_REMOVE(&ggioq->head, ggio, link);
			TAILQ_INSERT_TAIL(&ggio_freelist.head, ggio, link);
		}
	}

	if (disconnect)
		syslog(LOG_WARNING, "%s: interrupted", __func__);

	for (int i = 0; i < MAX_QUEUE_DEPTH; i++) {
		TAILQ_REMOVE(&ggio_freelist.head, &freelist[i], link);
		free(freelist[i].io.gctl_data);
	}
	ggioq_destroy(&ggio_freelist);
	free(freelist);

destroy:
	ggate_context_cancel(ggate, 0);
	ggate_context_destroy_device(ggate, true);

disconnect:
	for (int i = 0; i < nconns; i++) {
		conn = &connections[i];
		if (conn->state == DISCONNECTED)
			continue;
		if (nbd_client_send_disconnect(conn->nbd) == FAILURE)
			retval = FAILURE;
		nbd_client_shutdown(conn->nbd);
	}

close:
	for (int i = 0; i < nconns; i++)
		nbd_client_close(connections[i].nbd);
	ggate_context_close(ggate);

cleanup:
	pthread_rwlock_destroy(&flush_lock);
	for (int i = 0; i < nconns; i++) {
		conn = &connections[i];
		nbd_client_free(conn->nbd);
		cap_close(conn->capnet);
		ggioq_destroy(&conn->inflight);
		pthread_cond_destroy(&conn->flush_cond);
		pthread_cond_destroy(&conn->shutdown_cond);
		pthread_cond_destroy(&conn->reconnect_cond);
	}
	free(connections);
cleanup1:
	ggate_context_free(ggate);
	SSL_CTX_free(ssl_ctx);

	if (retval != SUCCESS)
		syslog(LOG_CRIT, "%s: device connection failed", __func__);

	assert(!list);
	return (retval);
}
