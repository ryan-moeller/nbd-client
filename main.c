/*
 * Copyright (c) 2016-2025 Ryan Moeller
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/bio.h>
#include <sys/capsicum.h>
#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/syslimits.h>
#include <assert.h>
#include <capsicum_helpers.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
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
#include "nbd-client.h"
#include "nbd-protocol.h"

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#define SSL_CTX_load_verify_file(ctx, file) \
    SSL_CTX_load_verify_locations((ctx), (file), NULL)
#endif

enum {
	DEFAULT_SECTOR_SIZE = 512,
	DEFAULT_GGATE_FLAGS = 0,
};

static void
usage()
{

	fprintf(stderr, "usage: %s "
		"[-fl] [-n export] [[-A cacert] -C cert -K key] "
		"host [port]\n",
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
	return SUCCESS;
}

static volatile sig_atomic_t disconnect = 0;

static void
signal_handler(int sig, siginfo_t *sinfo, void *uap)
{

	disconnect = 1;
}

static inline char const *
bio_cmd_string(uint16_t cmd)
{

	switch (cmd) {

#define CASE_MESSAGE(c) case c: return #c

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

	default: return NULL;
	}
}

enum loop_state {
	SETUP,
	START,
	DO_CMD,
	RECV_HEADER,
	RECV_DATA,
	END_CMD,
	FINISHED,
	FAIL
};

struct loop_context {
	ggate_context_t ggate;
	nbd_client_t nbd;
	struct g_gate_ctl_io ggio;
	uint8_t *buf;
	size_t buflen;
};

static inline enum loop_state
loop_init(struct loop_context *ctx,
	  ggate_context_t ggate,
	  nbd_client_t nbd,
	  uint8_t *buf, size_t buflen)
{

	ctx->ggate = ggate;
	ctx->nbd = nbd;
	ctx->ggio = (struct g_gate_ctl_io){
		.gctl_version = G_GATE_VERSION,
		.gctl_unit = ggate_context_get_unit(ggate),
	};
        ctx->buf = buf;
        ctx->buflen = buflen;

	return SETUP;
}

static inline enum loop_state
loop_setup(struct loop_context *ctx)
{

	ctx->ggio.gctl_data = ctx->buf;
	ctx->ggio.gctl_length = ctx->buflen;
	ctx->ggio.gctl_error = 0;

	return START;
}

static inline int
ggioctl(struct loop_context *ctx, uint64_t req)
{

	return ggate_context_ioctl(ctx->ggate, req, &ctx->ggio);
}

static inline enum loop_state
loop_start(struct loop_context *ctx)
{
	int result;

	result = ggioctl(ctx, G_GATE_CMD_START);

	if (result == FAILURE) {
		return FAIL;
	}

	switch (ctx->ggio.gctl_error) {
	case SUCCESS:
		return DO_CMD;

	case ECANCELED:
		return FINISHED;

	case ENXIO:
	default:
		syslog(LOG_ERR, "%s: ggate control operation failed: %s",
		       __func__, strerror(ctx->ggio.gctl_error));
		return FAIL;
	}
}

static inline int
nbdcmd(struct loop_context *ctx)
{

	switch (ctx->ggio.gctl_cmd) {
	case BIO_READ:
		return nbd_client_send_read(ctx->nbd,
					    ctx->ggio.gctl_seq,
					    ctx->ggio.gctl_offset,
					    ctx->ggio.gctl_length);

	case BIO_WRITE:
		return nbd_client_send_write(ctx->nbd,
					     ctx->ggio.gctl_seq,
					     ctx->ggio.gctl_offset,
					     ctx->ggio.gctl_length,
					     ctx->buflen, ctx->buf);

	case BIO_DELETE:
		return nbd_client_send_trim(ctx->nbd,
					    ctx->ggio.gctl_seq,
					    ctx->ggio.gctl_offset,
					    ctx->ggio.gctl_length);

	case BIO_FLUSH:
		return nbd_client_send_flush(ctx->nbd, ctx->ggio.gctl_seq);

	default:
		syslog(LOG_NOTICE, "%s: unsupported operation: %d",
		       __func__, ctx->ggio.gctl_cmd);
		return EOPNOTSUPP;
	}
}

static inline enum loop_state
loop_command(struct loop_context *ctx)
{
	int result;

	result = nbdcmd(ctx);

	switch (result) {
	case SUCCESS:
		return RECV_HEADER;

	case EOPNOTSUPP:
		ctx->ggio.gctl_error = EOPNOTSUPP;
		return END_CMD;

	case FAILURE:
		syslog(LOG_ERR, "%s: nbd client error", __func__);
		return FAIL;

	default:
		syslog(LOG_ERR, "%s: unhandled nbd command result: %d",
		       __func__, result);
		return FAIL;
	}
}

static inline enum loop_state
hdrinval(struct loop_context* ctx)
{
	char const *name;

	if (ctx->ggio.gctl_cmd == BIO_DELETE) {
		// Some servers lie about support for TRIM.
		nbd_client_disable_trim(ctx->nbd);
		ctx->ggio.gctl_error = EOPNOTSUPP;

		return END_CMD;
	}

	syslog(LOG_ERR, "%s: server rejected command request", __func__);

	name = bio_cmd_string(ctx->ggio.gctl_cmd);

	if (name == NULL)
		syslog(LOG_DEBUG, "\tcommand: %u (unknown)",
		       ctx->ggio.gctl_cmd);
	else
		syslog(LOG_DEBUG, "\tcommand: %s", name);

	syslog(LOG_DEBUG, "\toffset: %lx (%ld)",
	       ctx->ggio.gctl_offset, ctx->ggio.gctl_offset);
	syslog(LOG_DEBUG, "\tlength: %lx (%lu)",
	       ctx->ggio.gctl_length, ctx->ggio.gctl_length);

	return FAIL;
}

static inline enum loop_state
loop_recv_header(struct loop_context* ctx)
{
	int result;

	result = nbd_client_recv_reply_header(ctx->nbd, &ctx->ggio.gctl_seq);

	switch (result) {
	case SUCCESS:
		return (ctx->ggio.gctl_cmd == BIO_READ) ? RECV_DATA : END_CMD;

	case EINVAL:
		return hdrinval(ctx);

	default:
		if (disconnect) {
			return FINISHED;
		}
		else {
			syslog(LOG_ERR, "%s: error receiving reply header",
			       __func__);
			return FAIL;
		}
	}
}

static inline enum loop_state
loop_recv_data(struct loop_context *ctx)
{
	int result;

	result = nbd_client_recv_reply_data(ctx->nbd,
					    ctx->ggio.gctl_length,
					    ctx->buflen, ctx->buf);

	if (result == FAILURE) {
		if (disconnect) {
			return FINISHED;
		}
		else {
			syslog(LOG_ERR, "%s: error receiving reply data",
			       __func__);
			return FAIL;
		}
	}
	else {
		return END_CMD;
	}
}

static inline enum loop_state
loop_end_command(struct loop_context *ctx)
{
	int result;

	result = ggioctl(ctx, G_GATE_CMD_DONE);

	if (result == FAILURE) {
		syslog(LOG_ERR, "%s: could not complete transaction", __func__);
		return FAIL;
	}

	switch (ctx->ggio.gctl_error) {
	case SUCCESS:
	case EOPNOTSUPP:
		return SETUP;

	case ECANCELED:
		return FINISHED;

	case ENXIO:
	default:
		syslog(LOG_ERR, "%s: ggate control operation failed: %s",
		       __func__, strerror(ctx->ggio.gctl_error));
		return FAIL;
	}
}

int
run_loop(ggate_context_t ggate, nbd_client_t nbd)
{
	struct sigaction sa;
	uint8_t buf[MAXPHYS];
	struct loop_context context;
	struct loop_context *ctx;
	enum loop_state current_state;

	sa.sa_sigaction = signal_handler;
	sa.sa_flags = SA_SIGINFO;
	if (sigaction(SIGINT, &sa, NULL) == FAILURE) {
		syslog(LOG_ERR, "%s: failed to install signal handler: %m",
		       __func__);
		return FAILURE;
	}

	ctx = &context;
	current_state = loop_init(ctx, ggate, nbd, &buf[0], sizeof buf);

	while (!disconnect) {
		switch (current_state) {
		case SETUP:
			current_state = loop_setup(ctx);
			break;

		case START:
			current_state = loop_start(ctx);
			break;

		case DO_CMD:
			current_state = loop_command(ctx);
			break;

		case RECV_HEADER:
			current_state = loop_recv_header(ctx);
			break;

		case RECV_DATA:
			current_state = loop_recv_data(ctx);
			break;

		case END_CMD:
			current_state = loop_end_command(ctx);
			break;

		case FINISHED:
			return SUCCESS;

		case FAIL:
		default:
			ggate_context_cancel(ggate, context.ggio.gctl_seq);
			return FAILURE;
		}
	}

	nbd_client_set_disconnect(ctx->nbd, true);
	ggate_context_cancel(ggate, context.ggio.gctl_seq);
	return SUCCESS;
}

/* See http://archives.seul.org/libevent/users/Jan-2013/msg00039.html */
static int
cert_verify_callback(X509_STORE_CTX *x509_ctx, void *arg)
{
	char const *host = arg;
	X509 *server_cert;

	if (X509_verify_cert(x509_ctx) != 1)
		return 0;
	server_cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	if (validate_hostname(host, server_cert) != MatchFound) {
		syslog(LOG_ERR, "%s: failed to validate server hostname",
		       __func__);
		return 0;
	}
	return 1;
}

static cap_channel_t *
casper_enter_net(char const *host, char const *port)
{
	cap_channel_t *capcas, *capnet;
	cap_net_limit_t *limit;

	fclose(stdin);
	capcas = cap_init();
	if (capcas == NULL) {
		syslog(LOG_ERR, "%s: failed to initialize Casper",
		       __func__);
		return NULL;
	}
	caph_cache_catpages();
	if (caph_enter_casper() < 0) {
		syslog(LOG_ERR, "%s: failed to enter capability mode",
		       __func__);
		cap_close(capcas);
		return NULL;
	}
	capnet = cap_service_open(capcas, "system.net");
	cap_close(capcas);
	if (capnet == NULL) {
		syslog(LOG_ERR, "%s: failed to open system.net service",
		       __func__);
		return NULL;
	}
	limit = cap_net_limit_init(capnet,
				   CAPNET_NAME2ADDR | CAPNET_CONNECTDNS);
	if (limit == NULL) {
		syslog(LOG_ERR, "%s: failed to create limits", __func__);
		cap_close(capnet);
		return NULL;
	}
	cap_net_limit_name2addr(limit, host, port);
	if (cap_net_limit(limit) < 0) {
		syslog(LOG_ERR, "%s: failed to apply limits", __func__);
		cap_close(capnet);
		return NULL;
	}

	return capnet;
}

int
main(int argc, char *argv[])
{
	char ident[G_GATE_INFOSIZE];
	ggate_context_t ggate;
	nbd_client_t nbd;
	char const *name, *host, *port;
	char const *cacertfile, *certfile, *keyfile;
	cap_channel_t *capnet;
	struct addrinfo hints, *ai;
	uint64_t size;
	bool daemonize, list;
	int result, retval;

	retval = EXIT_FAILURE;
	name = "";
	cacertfile = certfile = keyfile = NULL;
	daemonize = true;
	list = false;
	ggate = NULL;
	nbd = NULL;

	/*
	 * Check the command line arguments.
	 */

	while ((result = getopt(argc, argv, "fln:A:C:K:")) != -1) {
		switch (result) {
		case 'f':
			daemonize = false;
			break;
		case 'l':
			list = true;
			break;
		case 'n':
			name = optarg;
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
		case '?':
		default:
			usage();
			return EXIT_FAILURE;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1 || argc > 2) {
		usage();
		return EXIT_FAILURE;
	}

	if (cacertfile != NULL && certfile == NULL) {
		usage();
		return EXIT_FAILURE;
	}
	if (certfile != NULL && keyfile == NULL) {
		usage();
		return EXIT_FAILURE;
	}
	if (keyfile != NULL && certfile == NULL) {
		usage();
		return EXIT_FAILURE;
	}

	host = argv[0];
	if (argc == 2)
		port = argv[1];
	else
		port = NBD_DEFAULT_PORT;

	snprintf(ident, sizeof ident, "%s (%s%s%s%s%s)", getprogname(), host,
		 strcmp(port, NBD_DEFAULT_PORT) == 0 ? "" : ":",
		 strcmp(port, NBD_DEFAULT_PORT) == 0 ? "" : port,
		 name[0] == '\0' ? "" : "/", name);

	/*
	 * Direct log messages to stderr if stderr is a TTY. Otherwise, log
	 * to syslog as well as to the console.
	 *
	 * LOG_NDELAY makes sure the connection to syslogd is opened before
	 * entering capability mode.
	 */

	if (isatty(fileno(stderr)))
		openlog(NULL, LOG_NDELAY | LOG_PERROR, LOG_USER);
	else
		openlog(ident, LOG_NDELAY | LOG_CONS | LOG_PID, LOG_DAEMON);

	if (!list) {
		/*
		 * Ensure the geom_gate module is loaded.
		 */

		if (ggate_load_module() == FAILURE)
			return EXIT_FAILURE;

		/*
		 * Allocate ggate context.
		 */
		ggate = ggate_context_alloc();
		if (ggate == NULL)
			goto cleanup;
	}

	/*
	 * Allocate nbd client.
	 */

	nbd = nbd_client_alloc();
	if (nbd == NULL)
		goto cleanup;

	/*
	 * Set up TLS if needed.
	 */

	if (certfile != NULL) {
		SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

		if (ctx == NULL) {
			ERR_print_errors_fp(stderr);
			syslog(LOG_ERR, "%s: failed to create TLS client",
			       __func__);
			goto close;
		}

		if (cacertfile != NULL &&
		    SSL_CTX_load_verify_file(ctx, cacertfile) != 1) {
			ERR_print_errors_fp(stderr);
			syslog(LOG_ERR, "%s: failed to load CA certificate %s",
			       __func__, cacertfile);
			SSL_CTX_free(ctx);
			goto close;
		}

		if (SSL_CTX_use_certificate_chain_file(ctx, certfile) != 1) {
			ERR_print_errors_fp(stderr);
			syslog(LOG_ERR,
			       "%s: failed to use certificate chain %s",
			       __func__, certfile);
			SSL_CTX_free(ctx);
			goto close;
		}

		if (SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM)
		    != 1) {
			ERR_print_errors_fp(stderr);
			syslog(LOG_ERR, "%s: failed to use private key %s",
			       __func__, keyfile);
			SSL_CTX_free(ctx);
			goto close;
		}

		if (SSL_CTX_check_private_key(ctx) != 1) {
			ERR_print_errors_fp(stderr);
			syslog(LOG_ERR, "%s: private key %s failed check",
			       __func__, keyfile);
			SSL_CTX_free(ctx);
			goto close;
		}

		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_cert_verify_callback(ctx, cert_verify_callback,
						 __DECONST(void *, host));
		SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
		SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
		nbd_client_set_ssl_ctx(nbd, ctx);
	}

	if (!list) {
		/*
		 * Try to daemonize unless instructed to stay in the foreground.
		 */

		if (daemonize) {
			if (daemon(0, 1) == FAILURE) {
				syslog(LOG_ERR, "%s: failed to daemonize: %m",
				       __func__);
				goto close;
			}
		}

		/*
		 * Initialize the ggate context.
		 */

		ggate_context_init(ggate);
		if (ggate_context_open(ggate) == FAILURE) {
			syslog(LOG_ERR, "%s: cannot open ggate context",
			       __func__);
			goto close;
		}
	}

	/*
	 * Set up Casper, enter capability mode, and get a handle to the
	 * system.net service limited to the given host/port.  Limit the rights
	 * on the ggate ctl descriptor now if needed.  The nbd socket rights are
	 * limited after the connection is established, as we don't have the
	 * socket at this time.
	 */

	capnet = casper_enter_net(host, port);
	if (capnet == NULL ||
	    (!list && ggate_context_rights_limit(ggate) == FAILURE))
		goto close;

	/*
	 * Connect to the nbd server.
	 */

	memset(&hints, 0, sizeof hints);
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
	result = nbd_client_connect(nbd, capnet, host, ai);
	freeaddrinfo(ai);
	cap_close(capnet);
	if (result == FAILURE) {
		syslog(LOG_ERR, "%s: failed to connect to server (%s:%s)",
		       __func__, host, port);
		goto close;
	}
	if (nbd_client_rights_limit(nbd) == FAILURE) {
		nbd_client_abort(nbd);
		nbd_client_shutdown(nbd);
		goto close;
	}

	if (list) {
		/*
		 * List server exports.
		 */

		retval = nbd_client_list(nbd, list_callback, NULL);
		nbd_client_abort(nbd);
		nbd_client_shutdown(nbd);
		goto close;
	}

	/*
	 * Negotiate options with the server.
	 */

	if (nbd_client_negotiate(nbd, name) == FAILURE) {
		syslog(LOG_ERR, "%s: failed to negotiate options", __func__);
		nbd_client_abort(nbd);
		nbd_client_shutdown(nbd);
		goto close;
	}

	size = nbd_client_get_size(nbd);

	/*
	 * Create the nbd device.
	 */

	if (ggate_context_create_device(ggate, ident, size,
					DEFAULT_SECTOR_SIZE,
					DEFAULT_GGATE_FLAGS) == FAILURE) {
		syslog(LOG_ERR, "%s:failed to create ggate device", __func__);
		goto destroy;
	}

	if (daemonize) {
		/*
		 * Now that we've printed the device name we can close
		 * stdout/stderr to complete the daemonization.
		 */

		fclose(stdout);
		fclose(stderr);
	}

	/*
	 * Handle operations on the ggate device.
	 */

	retval = run_loop(ggate, nbd);

	if (disconnect)
		syslog(LOG_WARNING, "%s: interrupted", __func__);

	/*
	 * Exit cleanly.
	 */

	/* Destroy the ggate device. */
 destroy:
	assert(!list);
	ggate_context_cancel(ggate, 0);
	ggate_context_destroy_device(ggate, true);

	/* Disconnect the NBD client. */
 disconnect:
	if (nbd_client_send_disconnect(nbd) == FAILURE)
		retval = FAILURE;
	nbd_client_shutdown(nbd);

	/* Close open files. */
 close:
	nbd_client_close(nbd);
	if (!list)
		ggate_context_close(ggate);

	/* Free data structures. */
 cleanup:
	nbd_client_free(nbd);
	if (!list)
		ggate_context_free(ggate);

	if (retval != SUCCESS)
		syslog(LOG_CRIT, "%s: device connection failed", __func__);

	return retval;
}
