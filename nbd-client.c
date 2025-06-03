/*
 * Copyright (c) 2016-2025 Ryan Moeller
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/syslimits.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "check.h"
#include "nbd-client.h"
#include "nbd-protocol.h"

enum {
	NBD_CLIENT_TIMEOUT = 8,
	NBD_REPLY_QUEUE_TIMEOUT = 1,
};

struct nbd_client {
	int sock;
	_Atomic(bool) disconnect;
	uint32_t flags;
	uint64_t size;
	char const *host;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	ssize_t (*send)(struct nbd_client *, void const *, size_t);
	ssize_t (*recv)(struct nbd_client *, void *, size_t);
};

struct nbd_client *
nbd_client_alloc()
{
	struct nbd_client *client;

	client = calloc(1, sizeof *client);
	if (client == NULL) {
		assert(errno == ENOMEM);
		syslog(LOG_ERR, "%s: failed to allocate nbd client: %m",
		       __func__);
	}

	return client;
}

void
nbd_client_free(struct nbd_client *client)
{
	SSL_free(client->ssl);
	SSL_CTX_free(client->ssl_ctx);
	free(__DECONST(char *, client->host));
	free(client);
}

static ssize_t
nbd_client_send(struct nbd_client *client, void const *buf, size_t len)
{
	return send(client->sock, buf, len, MSG_NOSIGNAL);
}

static ssize_t
nbd_client_recv(struct nbd_client *client, void *buf, size_t len)
{
	return recv(client->sock, buf, len, MSG_WAITALL);
}

static int
nbd_client_init(struct nbd_client *client, char const *host,
		struct addrinfo *ai)
{
	int sock;
	int on;

	on = 1;

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (sock == FAILURE) {
		syslog(LOG_ERR, "%s: failed to create socket: %m", __func__);
		return FAILURE;
	}

	if (ai->ai_family != AF_UNIX) {
		if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on)
		    == FAILURE) {
			syslog(LOG_ERR,
				"%s: failed to set socket option TCP_NODELAY: %m",
			       __func__);
			return FAILURE;
		}

		if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on)
		    == FAILURE) {
			syslog(LOG_ERR,
			       "%s: failed to set socket option SO_KEEPALIVE: %m",
			       __func__);
			return FAILURE;
		}
	}
	client->sock = sock;
	if (ai->ai_canonname != NULL)
		host = ai->ai_canonname;
	client->host = strdup(host);
	client->send = nbd_client_send;
	client->recv = nbd_client_recv;

	return SUCCESS;
}

void
nbd_client_close(struct nbd_client *client)
{

	close(client->sock);
}

int
nbd_client_rights_limit(struct nbd_client *client)
{
	cap_rights_t rights;

	cap_rights_init(&rights, CAP_SEND, CAP_RECV, CAP_SHUTDOWN);

	if (cap_rights_limit(client->sock, &rights) == FAILURE) {
		syslog(LOG_ERR, "%s: failed to limit capabilities: %m",
		       __func__);
		return FAILURE;
	}

	return SUCCESS;
}

uint64_t
nbd_client_get_size(struct nbd_client *client)
{

	return client->size;
}

bool
nbd_client_get_disconnect(struct nbd_client *client)
{

	return client->disconnect;
}

void
nbd_client_set_disconnect(struct nbd_client *client, bool disconnect)
{

	client->disconnect = disconnect;
}

void
nbd_client_disable_trim(struct nbd_client *client)
{

	client->flags &= ~NBD_FLAG_SEND_TRIM;
}

int
nbd_client_connect(struct nbd_client *client, char const *host,
		   struct addrinfo *first_ai)
{
	struct addrinfo *ai;
	int sock;

	for (ai = first_ai; ai != NULL; ai = ai->ai_next) {
		if (nbd_client_init(client, host, ai) == FAILURE)
			continue;
		sock = client->sock;
		if (connect(sock, ai->ai_addr, ai->ai_addrlen) == FAILURE) {
			close(sock);
			continue;
		}
		break;
	}
	if (ai == NULL) {
		syslog(LOG_ERR,
		       "%s: failed to connect to remote server (%s): %m",
		       __func__, host);
		return FAILURE;
	}
	return SUCCESS;
}

void
nbd_client_shutdown(struct nbd_client *client)
{

	shutdown(client->sock, SHUT_RDWR);
}

static inline char const *
nbd_client_flag_string(uint32_t flag)
{

	switch (flag) {

#define CASE_MESSAGE(c) case c: return #c

		CASE_MESSAGE(NBD_FLAG_HAS_FLAGS);
		CASE_MESSAGE(NBD_FLAG_READ_ONLY);
		CASE_MESSAGE(NBD_FLAG_SEND_FLUSH);
		CASE_MESSAGE(NBD_FLAG_SEND_FUA);
		CASE_MESSAGE(NBD_FLAG_ROTATIONAL);
		CASE_MESSAGE(NBD_FLAG_SEND_TRIM);

#undef CASE_MESSAGE

	default: return NULL;
	}
}

static inline void
nbd_client_dump(struct nbd_client *client)
{
	const uint32_t Flags[] = {
		NBD_FLAG_HAS_FLAGS, NBD_FLAG_READ_ONLY, NBD_FLAG_SEND_FLUSH,
		NBD_FLAG_SEND_FUA, NBD_FLAG_ROTATIONAL, NBD_FLAG_SEND_TRIM,
	};
	const size_t FlagsLen = sizeof Flags / sizeof Flags[0];

	char flag_string[128], *curflag;
	uint32_t flags;
	size_t i, len;

	syslog(LOG_DEBUG, "\tsock: %d", client->sock);
	syslog(LOG_DEBUG, "\tdisconnect: %s",
	       client->disconnect ? "true" : "false");
	syslog(LOG_DEBUG, "\thost: %s", client->host);
	flags = client->flags;
	curflag = flag_string;
	len = sizeof flag_string;
	i = FlagsLen;
	while (len && i--) {
		char const *name;
		size_t namelen, t;
		uint32_t value;
		bool match, last;

		value = Flags[i];
		name = nbd_client_flag_string(value);
		namelen = strlen(name);
		match = (flags & value) != 0;
		last = i > 0;

		assert(name != NULL);

		snprintf(curflag, len, "%s%s", match ? name : "",
			 last ? (match ? "|" : "") : "");

		t = namelen + (match ? 1 : 0); // doesn't matter on last
		curflag += t;
		len -= t;
	}
	syslog(LOG_DEBUG, "\tflags: %#010x [%s]", flags, flag_string);
	syslog(LOG_DEBUG, "\tsize: %lu", client->size);
}

void
nbd_client_set_ssl_ctx(struct nbd_client *client, SSL_CTX *ssl_ctx)
{
	client->ssl_ctx = ssl_ctx;
}

static inline void
nbd_oldstyle_negotiation_ntoh(struct nbd_oldstyle_negotiation *handshake)
{

	handshake->size = be64toh(handshake->size);
	handshake->flags = be32toh(handshake->flags);
}

static inline bool
nbd_oldstyle_negotiation_is_valid(struct nbd_oldstyle_negotiation *handshake)
{

	if (!(handshake->flags & NBD_FLAG_HAS_FLAGS)) {
		syslog(LOG_ERR,
		       "%s: invalid flags: %#010x (expected low bit set)",
		       __func__, handshake->flags);
		return false;
	}

	return true;
}

static inline void
nbd_oldstyle_negotiation_dump(struct nbd_oldstyle_negotiation *handshake)
{
	uint32_t flags = handshake->flags;

	syslog(LOG_DEBUG, "\tsize: %lu", handshake->size);
	syslog(LOG_DEBUG, "\tflags: %#010x%s", flags,
	       (flags & NBD_FLAG_HAS_FLAGS) ? "" : " (invalid)");
}

static int
nbd_client_oldstyle_handshake(struct nbd_client *client)
{
	struct nbd_oldstyle_negotiation handshake;
	ssize_t len;

	while (true) {
		len = client->recv(client, &handshake, sizeof handshake);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len != sizeof handshake) {
			syslog(LOG_ERR, "%s: connection failed: %m", __func__);
			return FAILURE;
		}
		break;
	}

	nbd_oldstyle_negotiation_ntoh(&handshake);

	//syslog(LOG_DEBUG, "%s: negotiation", __func__);
	//nbd_oldstyle_negotiation_dump(&handshake);

	if (!nbd_oldstyle_negotiation_is_valid(&handshake)) {
		syslog(LOG_ERR, "%s: invalid handshake", __func__);
		nbd_oldstyle_negotiation_dump(&handshake);
		return FAILURE;
	}

	client->size = handshake.size;
	client->flags = handshake.flags;

	//syslog(LOG_DEBUG, "%s: client", __func__);
	//nbd_client_dump(client);

	if (!(handshake.flags & NBD_FLAG_SEND_FLUSH))
		syslog(LOG_INFO,
		       "%s: server does not support FLUSH command", __func__);
	if (!(handshake.flags & NBD_FLAG_SEND_TRIM))
		syslog(LOG_INFO,
		       "%s: server does not support TRIM command", __func__);

	return SUCCESS;
}

static inline void
nbd_newstyle_negotiation_ntoh(struct nbd_newstyle_negotiation *handshake)
{

	handshake->handshake_flags = be16toh(handshake->handshake_flags);
}

#define VALID_NEWSTYLE_FLAGS (NBD_FLAG_FIXED_NEWSTYLE|NBD_FLAG_NO_ZEROES)

static inline bool
nbd_newstyle_negotiation_is_valid(struct nbd_newstyle_negotiation *handshake)
{
	uint16_t flags = handshake->handshake_flags;

	if (flags & ~VALID_NEWSTYLE_FLAGS)
		syslog(LOG_ERR, "%s: ignoring unknown handshake flags: %#06x",
		       __func__, flags);
	if (!(flags & NBD_FLAG_FIXED_NEWSTYLE)) {
		syslog(LOG_ERR, "%s: this server does not support the fixed "
		       "newstyle protocol", __func__);
		return false;
	}

	return true;
}

static inline void
nbd_newstyle_negotiation_dump(struct nbd_newstyle_negotiation *handshake)
{
	uint16_t flags = handshake->handshake_flags;

	syslog(LOG_DEBUG, "\thandshake_flags: %#06x [%s%s%s]%s", flags,
	       (flags & NBD_FLAG_FIXED_NEWSTYLE) ? "FIXED_NEWSTYLE" : "",
	       ((flags & VALID_NEWSTYLE_FLAGS)
		== VALID_NEWSTYLE_FLAGS) ? "|" : "",
	       (flags & NBD_FLAG_NO_ZEROES) ? "NO_ZEROES" : "",
	       (flags & ~VALID_NEWSTYLE_FLAGS) ? " (invalid)" : "");
}

static inline void
nbd_client_flags_set_client_flags(struct nbd_client_flags *client_flags,
				  uint32_t flags)
{

	client_flags->client_flags = htobe32(flags);
}

/*
 * Client handshake
 *
 * If the client and server agree not to send the reserved portion of the
 * EXPORT_NAME option reply, 1 is returned, otherwise 0.
 *
 * Returns -1 if an error is encountered.
 */
static int
nbd_client_newstyle_handshake(struct nbd_client *client)
{
	struct nbd_newstyle_negotiation handshake;
	struct nbd_client_flags response;
	uint32_t client_flags;
	ssize_t len;

	while (true) {
		len = client->recv(client, &handshake, sizeof handshake);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len != sizeof handshake)
			goto connection_fail;
		break;
	}

	nbd_newstyle_negotiation_ntoh(&handshake);

	if (!nbd_newstyle_negotiation_is_valid(&handshake)) {
		syslog(LOG_ERR, "%s: invalid handshake", __func__);
		nbd_newstyle_negotiation_dump(&handshake);
		return FAILURE;
	}

	client_flags = NBD_CLIENT_FLAG_FIXED_NEWSTYLE;
	if (handshake.handshake_flags & NBD_FLAG_NO_ZEROES)
		client_flags |= NBD_CLIENT_FLAG_NO_ZEROES;

	nbd_client_flags_set_client_flags(&response, client_flags);

	len = client->send(client, &response, sizeof response);
	if (len != sizeof response)
		goto connection_fail;

	client->flags = handshake.handshake_flags << 16;

	return SUCCESS;

 connection_fail:
	syslog(LOG_ERR, "%s: connection failed: %m", __func__);
	return FAILURE;
}

static inline void
nbd_option_init(struct nbd_option *option)
{

	memset(option, 0, sizeof *option);
	option->magic = htobe64(NBD_OPTION_MAGIC);
}

static inline void
nbd_option_set_option(struct nbd_option *option, uint32_t opt)
{

	option->option = htobe32(opt);
}

static inline void
nbd_option_set_length(struct nbd_option *option, uint32_t length)
{

	option->length = htobe32(length);
}

static int
nbd_client_send_option(struct nbd_client *client,
		       struct nbd_option *option,
		       size_t length, uint8_t const *data)
{
	ssize_t len;

	len = client->send(client, option, sizeof *option);
	if (len != sizeof *option)
		goto connection_fail;

	if (length == 0)
		return SUCCESS;

	assert(data != NULL);

	len = client->send(client, data, length);
	if (len != length)
		goto connection_fail;

	return SUCCESS;

 connection_fail:
	syslog(LOG_ERR, "%s: connection failed: %m", __func__);
	return FAILURE;
}

static inline void
nbd_option_reply_ntoh(struct nbd_option_reply *reply)
{

	reply->magic = be64toh(reply->magic);
	reply->option = be32toh(reply->option);
	reply->type = be32toh(reply->type);
	reply->length = be32toh(reply->length);
}

static inline bool
nbd_option_reply_is_valid(struct nbd_option_reply *reply,
			  struct nbd_option *option)
{
	uint32_t opt;

	opt = be32toh(option->option);

	assert(opt != NBD_OPTION_EXPORT_NAME);

	if (reply->magic != NBD_OPTION_REPLY_MAGIC) {
		syslog(LOG_ERR,
		       "%s: invalid magic: %#018lx (expected %#018lx)",
		       __func__, reply->magic, NBD_OPTION_REPLY_MAGIC);
		return false;
	}
	if (reply->option != opt) {
		syslog(LOG_ERR,
		       "%s: unexpected option: %#010x (expected %#010x)",
		       __func__, reply->option, opt);
		return false;
	}

	return true;
}

static inline char const *
nbd_option_reply_option_string(struct nbd_option_reply *reply)
{

	switch (reply->option) {

#define CASE_MESSAGE(c) case c: return #c
#define EXTENSION " [unsupported extension]"
#define WITHDRAWN " [withdrawn]"

		CASE_MESSAGE(NBD_OPTION_EXPORT_NAME);
		CASE_MESSAGE(NBD_OPTION_ABORT);
		CASE_MESSAGE(NBD_OPTION_LIST);
		CASE_MESSAGE(NBD_OPTION_PEEK_EXPORT) WITHDRAWN;
		CASE_MESSAGE(NBD_OPTION_STARTTLS);
		CASE_MESSAGE(NBD_OPTION_INFO) EXTENSION;
		CASE_MESSAGE(NBD_OPTION_GO) EXTENSION;
		CASE_MESSAGE(NBD_OPTION_STRUCTURED_REPLY) EXTENSION;
		CASE_MESSAGE(NBD_OPTION_BLOCK_SIZE) EXTENSION;

#undef WITHDRAWN
#undef EXTENSION
#undef CASE_MESSAGE

	default: return NULL;
	}
}

static inline char const *
nbd_option_reply_type_string(struct nbd_option_reply *reply)
{

	switch (reply->type) {

#define CASE_MESSAGE(c) case c: return #c
#define EXTENSION " [unsupported extension]"
#define UNUSED    " [unused]"
#define TODO      " [todo]"

		CASE_MESSAGE(NBD_REPLY_ACK);
		CASE_MESSAGE(NBD_REPLY_SERVER);
		CASE_MESSAGE(NBD_REPLY_INFO) EXTENSION;
		CASE_MESSAGE(NBD_REPLY_ERROR_UNSUPPORTED);
		CASE_MESSAGE(NBD_REPLY_ERROR_POLICY);
		CASE_MESSAGE(NBD_REPLY_ERROR_INVALID);
		CASE_MESSAGE(NBD_REPLY_ERROR_PLATFORM) UNUSED;
		CASE_MESSAGE(NBD_REPLY_ERROR_TLS_REQUIRED) TODO;
		CASE_MESSAGE(NBD_REPLY_ERROR_UNKNOWN) EXTENSION;
		CASE_MESSAGE(NBD_REPLY_ERROR_SHUTDOWN);
		CASE_MESSAGE(NBD_REPLY_ERROR_BLOCK_SIZE_REQD) EXTENSION;

#undef TODO
#undef UNUSED
#undef EXTENSION
#undef CASE_MESSAGE

	default: return NULL;
	}
}

static inline void
nbd_option_reply_dump(struct nbd_option_reply *reply)
{
	char const *option = nbd_option_reply_option_string(reply);
	char const *type = nbd_option_reply_type_string(reply);

	syslog(LOG_DEBUG, "\tmagic: %#018lx", reply->magic);

	if (option == NULL)
		syslog(LOG_DEBUG, "\toption: [unknown] %#010x (%d)",
		       reply->option, reply->option);
	else
		syslog(LOG_DEBUG, "\toption: %s", option);

	if (type == NULL)
		syslog(LOG_DEBUG, "\ttype: [unknown] %#010x (%d)",
		       reply->type, reply->type);
	else
		syslog(LOG_DEBUG, "\ttype: %s", type);

	syslog(LOG_DEBUG, "\tlength: %u", reply->length);
}

static int
nbd_client_recv_option_reply(struct nbd_client *client,
			     struct nbd_option *option,
			     struct nbd_option_reply *reply,
			     size_t datalen, uint8_t *data)
{
	size_t recvlen;
	ssize_t len;

	while (true) {
		len = client->recv(client, reply, sizeof *reply);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len != sizeof *reply)
			goto connection_fail;
		break;
	}

	nbd_option_reply_ntoh(reply);

	if (!nbd_option_reply_is_valid(reply, option)) {
		syslog(LOG_ERR, "%s: invalid option reply", __func__);
		nbd_option_reply_dump(reply);
		return FAILURE;
	}

	if (reply->length == 0)
		return SUCCESS;

	if (datalen == 0)
		return MOREDATA;

	assert(data != NULL);

	recvlen = MIN(reply->length, datalen);

	while (true) {
		len = client->recv(client, data, recvlen);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len != recvlen)
			goto connection_fail;
		break;
	}

	if (recvlen > datalen)
		return MOREDATA;

	return SUCCESS;

 connection_fail:
	syslog(LOG_ERR, "%s: connection failed: %m", __func__);
	return FAILURE;
}

static ssize_t
nbd_client_send_tls(struct nbd_client *client, void const *buf, size_t len)
{
	size_t amount, resid = len;

	do {
		if (SSL_write_ex(client->ssl, buf, len, &amount) != 1)
			return -1;
		buf += amount;
		resid -= amount;
	} while (resid > 0);

	return len;
}

static ssize_t
nbd_client_recv_tls(struct nbd_client *client, void *buf, size_t len)
{
	size_t amount, resid = len;

	do {
		if (SSL_read_ex(client->ssl, buf, len, &amount) != 1)
			return -1;
		buf += amount;
		resid -= amount;
	} while (resid > 0);

	return len;
}

static int
nbd_client_starttls(struct nbd_client *client)
{
	struct nbd_option option;
	struct nbd_option_reply reply;
	SSL *ssl;

	nbd_option_init(&option);
	nbd_option_set_option(&option, NBD_OPTION_STARTTLS);
	if (nbd_client_send_option(client, &option, 0, NULL)
	    == FAILURE) {
		syslog(LOG_ERR, "%s: sending STARTTLS option failed", __func__);
		return FAILURE;
	}
	if (nbd_client_recv_option_reply(client, &option, &reply, 0, NULL)
	    == FAILURE) {
		syslog(LOG_ERR, "%s: receiving STARTTLS option reply failed",
		       __func__);
		return FAILURE;
	}
	if (reply.type != NBD_REPLY_ACK) {
		syslog(LOG_ERR, "%s: server does not support TLS", __func__);
		return FAILURE;
	}

	ssl = SSL_new(client->ssl_ctx);
	if (ssl == NULL) {
		ERR_print_errors_fp(stderr);
		syslog(LOG_ERR, "%s: SSL_new failed", __func__);
		return FAILURE;
	}
	if (SSL_set_tlsext_host_name(ssl, client->host) != 1) {
		ERR_print_errors_fp(stderr);
		SSL_free(ssl);
		syslog(LOG_ERR, "%s: failed to set TLS server name", __func__);
		return FAILURE;
	}
	if (SSL_set_fd(ssl, client->sock) != 1) {
		ERR_print_errors_fp(stderr);
		SSL_free(ssl);
		syslog(LOG_ERR, "%s: failed to set TLS socket file descriptor",
		       __func__);
		return FAILURE;
	}
	if (SSL_connect(ssl) != 1) {
		ERR_print_errors_fp(stderr);
		SSL_free(ssl);
		syslog(LOG_ERR, "%s: TLS handshake failed", __func__);
		return FAILURE;
	}
	/* TODO: support multiple connections */
	SSL_CTX_free(client->ssl_ctx);
	client->ssl_ctx = NULL;
	client->ssl = ssl;
	client->send = nbd_client_send_tls;
	client->recv = nbd_client_recv_tls;
	return SUCCESS;
}

static inline void
nbd_export_info_ntoh(struct nbd_export_info *info)
{

	info->size = be64toh(info->size);
	info->transmission_flags = be16toh(info->transmission_flags);
}

static int
nbd_client_recv_export_info(struct nbd_client *client,
			    struct nbd_export_info *info)
{
	static size_t const SHORT_INFO_LEN =
		sizeof *info - sizeof info->reserved;
	ssize_t len;

	while (true) {
		len = client->recv(client, info, SHORT_INFO_LEN);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len != SHORT_INFO_LEN)
			goto connection_fail;
		break;
	}

	nbd_export_info_ntoh(info);

	client->size = info->size;
	client->flags |= info->transmission_flags;

	if ((client->flags >> 16) & NBD_FLAG_NO_ZEROES)
		return SUCCESS;

	while (true) {
		len = client->recv(client, info + SHORT_INFO_LEN,
				   sizeof info->reserved);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len != sizeof info->reserved)
			goto connection_fail;
		break;
	}

	return SUCCESS;

 connection_fail:
	syslog(LOG_ERR, "%s: connection failed: %m", __func__);
	return FAILURE;
}

static int
nbd_client_negotiate_options_fixed_newstyle(struct nbd_client *client,
					    char const *name)
{
	struct nbd_option option;
	struct nbd_export_info info;
	size_t namelen;

	namelen = strlen(name);
	nbd_option_init(&option);
	nbd_option_set_option(&option, NBD_OPTION_EXPORT_NAME);
	nbd_option_set_length(&option, namelen);
	if (nbd_client_send_option(client, &option, namelen,
				   (uint8_t const *)name) == FAILURE) {
		syslog(LOG_ERR, "%s: sending option EXPORT_NAME failed",
		       __func__);
		return FAILURE;
	}
	if (nbd_client_recv_export_info(client, &info) == FAILURE) {
		syslog(LOG_ERR, "%s: receiving export info failed",
		       __func__);
		return FAILURE;
	}

	if (!(info.transmission_flags & NBD_FLAG_SEND_FLUSH))
		syslog(LOG_INFO, "%s: server does not support FLUSH command",
		       __func__);
	if (!(info.transmission_flags & NBD_FLAG_SEND_TRIM))
		syslog(LOG_INFO, "%s: server does not support TRIM command",
		       __func__);

	return SUCCESS;
}

static inline void
nbd_option_reply_server_ntoh(struct nbd_option_reply_server *server_export)
{

	server_export->length = be32toh(server_export->length);
}

#ifndef NBD_REPLY_SERVER_LIMIT
#define NBD_REPLY_SERVER_LIMIT  (4 * PAGE_SIZE) /* arbitrary safeguard */
#endif

static int
nbd_client_negotiate_list_fixed_newstyle(struct nbd_client *client,
					 nbd_client_list_cb cb, void *ctx)
{
	struct nbd_option option;
	struct nbd_option_reply reply;
	struct nbd_option_reply_server server_export;
	char *name, *description;
	size_t resid;
	ssize_t len;
	int rc;

	nbd_option_init(&option);
	nbd_option_set_option(&option, NBD_OPTION_LIST);
	if (nbd_client_send_option(client, &option, 0, NULL) == FAILURE) {
		syslog(LOG_ERR, "%s: sending option LIST failed", __func__);
		return FAILURE;
	}
	while (true) {
		rc = nbd_client_recv_option_reply(client, &option, &reply,
						  sizeof(server_export),
						  (uint8_t *)&server_export);
		if (rc == FAILURE) {
			syslog(LOG_ERR,
			       "%s: receiving option LIST reply failed",
			       __func__);
			return FAILURE;
		}
		if (reply.type == NBD_REPLY_ACK)
			break;
		if (reply.type != NBD_REPLY_SERVER) {
			char const *msg;

			msg = nbd_option_reply_type_string(&reply);
			if (msg == NULL) {
				syslog(LOG_ERR, "%s: unknown server error (%d)",
				       __func__, reply.type);
			} else {
				syslog(LOG_ERR, "%s: server error: %s",
				       __func__, msg);
			}

			nbd_option_reply_dump(&reply);

			return FAILURE;
		}
		/* Don't let the network do unbounded allocations. */
		if (reply.length > NBD_REPLY_SERVER_LIMIT) {
			syslog(LOG_ERR, "%s: server reply is too big",
			       __func__);

			nbd_option_reply_dump(&reply);

			return FAILURE;
		}

		nbd_option_reply_server_ntoh(&server_export);
		assert((server_export.length + 4) <= reply.length);
		if (server_export.length == 0)
			name = NULL;
		else {
			resid = server_export.length;
			name = malloc(resid + 1);
			assert(name != NULL); /* hard to handle ENOMEM */
			while (true) {
				len = client->recv(client, name, resid);
				if (client->disconnect) {
					free(name);
					return FAILURE;
				}
				if (len == -1 && errno == EINTR)
					continue;
				if (len != resid) {
					free(name);
					syslog(LOG_ERR,
					       "%s: connection failed: %m",
					       __func__);
					return FAILURE;
				}
				break;
			}
			name[resid] = '\0';
		}
		resid = reply.length - (4 + server_export.length);
		if (resid == 0)
			description = NULL;
		else {
			description = malloc(resid + 1);
			assert(description != NULL); /* hard to handle ENOMEM */
			while (true) {
				len = client->recv(client, description, resid);
				if (client->disconnect) {
					free(description);
					free(name);
					return FAILURE;
				}
				if (len == -1 && errno == EINTR)
					continue;
				if (len != resid) {
					free(description);
					free(name);
					syslog(LOG_ERR,
					       "%s: connection failed: %m",
					       __func__);
					return FAILURE;
				}
				break;
			}
			description[resid] = '\0';
		}
		rc = cb(ctx, name, description);
		if (rc != SUCCESS)
			return rc;
	}

	return SUCCESS;
}

static inline void
nbd_handshake_magic_ntoh(struct nbd_handshake_magic *handshake)
{

	handshake->magic = be64toh(handshake->magic);
	handshake->style = be64toh(handshake->style);
}

static inline void
nbd_handshake_magic_dump(struct nbd_handshake_magic *handshake)
{

	syslog(LOG_DEBUG, "\tmagic: %#018lx (expected %#018lx)",
	       handshake->magic, NBD_MAGIC);
	syslog(LOG_DEBUG, "\tstyle: %#018lx (expected %#018lx or %#018lx)",
	       handshake->style, NBD_OLDSTYLE_MAGIC, NBD_NEWSTYLE_MAGIC);
}

int
nbd_client_negotiate(struct nbd_client *client, char const *name)
{
	struct nbd_handshake_magic handshake;
	ssize_t len;

	while (true) {
		len = client->recv(client, &handshake, sizeof handshake);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len == -1) {
			syslog(LOG_ERR, "%s: connection failed: %m", __func__);
			return FAILURE;
		}
		if (len == sizeof handshake)
			break;
	}

	nbd_handshake_magic_ntoh(&handshake);

	if (handshake.magic != NBD_MAGIC) {
		syslog(LOG_ERR, "%s: handshake failed: invalid magic", __func__);
		return FAILURE;
	}

	if (handshake.style == NBD_OLDSTYLE_MAGIC) {

		syslog(LOG_INFO, "%s: oldstyle handshake detected", __func__);

		if (name[0] != '\0') {
			syslog(LOG_ERR, "%s: server does not support named "
			       "exports", __func__);
			return FAILURE;
		}

		if (client->ssl_ctx != NULL) {
			syslog(LOG_ERR, "%s: server does not support TLS",
			       __func__);
			return FAILURE;
		}

		if (nbd_client_oldstyle_handshake(client) == FAILURE) {
			syslog(LOG_ERR, "%s: handshake failed", __func__);
			return FAILURE;
		}

		return SUCCESS;

	} else if (handshake.style == NBD_NEWSTYLE_MAGIC) {

		syslog(LOG_INFO, "%s: newstyle handshake detected", __func__);

		if (nbd_client_newstyle_handshake(client) == FAILURE) {
			syslog(LOG_ERR, "%s: handshake failed", __func__);
			return FAILURE;
		}

		if (client->ssl_ctx != NULL &&
		    nbd_client_starttls(client) == FAILURE) {
			syslog(LOG_ERR, "%s: STARTTLS failed", __func__);
			return FAILURE;
		}

		if (nbd_client_negotiate_options_fixed_newstyle(client, name)
		    == FAILURE) {
			syslog(LOG_ERR, "%s: option negotiation failed",
			       __func__);
			return FAILURE;
		}

		return SUCCESS;

	}

	syslog(LOG_ERR, "%s: handshake failed: unknown style", __func__);
	nbd_handshake_magic_dump(&handshake);

	return FAILURE;
}

int
nbd_client_list(struct nbd_client *client, nbd_client_list_cb cb, void *ctx)
{
	struct nbd_handshake_magic handshake;
	ssize_t len;

	while (true) {
		len = client->recv(client, &handshake, sizeof handshake);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len == -1) {
			syslog(LOG_ERR, "%s: connection failed: %m", __func__);
			return FAILURE;
		}
		if (len == sizeof handshake)
			break;
	}

	nbd_handshake_magic_ntoh(&handshake);

	if (handshake.magic != NBD_MAGIC) {
		syslog(LOG_ERR, "%s: handshake failed: invalid magic", __func__);
		return FAILURE;
	}

	if (handshake.style == NBD_OLDSTYLE_MAGIC)
		/* Fake it. */
		return cb(ctx, NULL, NULL);

	if (handshake.style != NBD_NEWSTYLE_MAGIC) {
		syslog(LOG_ERR, "%s: handshake failed: unknown style", __func__);
		nbd_handshake_magic_dump(&handshake);
		return FAILURE;
	}

	if (nbd_client_newstyle_handshake(client) == FAILURE) {
		syslog(LOG_ERR, "%s: handshake failed", __func__);
		return FAILURE;
	}

	if (client->ssl_ctx != NULL &&
	    nbd_client_starttls(client) == FAILURE) {
		syslog(LOG_ERR, "%s: STARTTLS failed", __func__);
		return FAILURE;
	}

	if (nbd_client_negotiate_list_fixed_newstyle(client, cb, ctx)
	    == FAILURE) {
		syslog(LOG_ERR, "%s: server listing failed", __func__);
		return FAILURE;
	}

	return SUCCESS;
}

static inline void
nbd_request_init(struct nbd_request *request)
{

	memset(request, 0,  sizeof *request);
	request->magic = htobe32(NBD_REQUEST_MAGIC);
}

static inline void
nbd_request_set_flags(struct nbd_request *request, uint16_t flags)
{

	request->flags = htobe16(flags);
}

static inline void
nbd_request_set_command(struct nbd_request *request, uint16_t command)
{

	request->command = htobe16(command);
}

static inline void
nbd_request_set_handle(struct nbd_request *request, uint64_t handle)
{

	request->handle = htobe64(handle);
}

static inline void
nbd_request_set_offset(struct nbd_request *request, uint64_t offset)
{

	request->offset = htobe64(offset);
}

static inline void
nbd_request_set_length(struct nbd_request *request, uint32_t length)
{

	request->length = htobe32(length);
}

static int
nbd_client_send_request(struct nbd_client *client, uint16_t command,
			uint64_t handle, off_t offset, size_t length,
			size_t datalen, uint8_t *data)
{
	struct nbd_request request;
	size_t sendlen;
	ssize_t len;

	assert(offset + length <= client->size);

	nbd_request_init(&request);
	nbd_request_set_flags(&request, 0);
	nbd_request_set_command(&request, command);
	nbd_request_set_handle(&request, handle);
	nbd_request_set_offset(&request, offset);
	nbd_request_set_length(&request, length);

	len = client->send(client, &request, sizeof request);
	if (len != sizeof request) {
		syslog(LOG_ERR, "%s: failed to send request header", __func__);
		goto connection_fail;
	}

	if (datalen == 0)
		return SUCCESS;

	assert(data != NULL);

	sendlen = MIN(length, datalen);

	len = client->send(client, data, sendlen);
	if (len != sendlen) {
		syslog(LOG_ERR, "%s: failed to send request data", __func__);
		goto connection_fail;
	}

	if (sendlen < length)
		return MOREDATA;

	return SUCCESS;

 connection_fail:
	syslog(LOG_ERR, "%s: connection failed: %m", __func__);
	return FAILURE;
}

int
nbd_client_send_read(struct nbd_client *client, uint64_t handle,
		     off_t offset, size_t length)
{

	return nbd_client_send_request(client, NBD_CMD_READ, handle,
				       offset, length, 0, NULL);
}

int
nbd_client_send_write(struct nbd_client *client, uint64_t handle,
		      off_t offset, size_t length,
		      size_t datalen, uint8_t *data)
{

	return nbd_client_send_request(client, NBD_CMD_WRITE, handle,
				       offset, length, datalen, data);
}

int
nbd_client_send_flush(struct nbd_client *client, uint64_t handle)
{

	if (!(client->flags & NBD_FLAG_SEND_FLUSH)) {
		syslog(LOG_NOTICE, "%s: unsupported FLUSH operation", __func__);
		return EOPNOTSUPP;
	}

	return nbd_client_send_request(client, NBD_CMD_FLUSH, handle,
				       0, 0, 0, NULL);
}

int
nbd_client_send_trim(struct nbd_client *client, uint64_t handle,
		     off_t offset, size_t length)
{

	if (!(client->flags & NBD_FLAG_SEND_TRIM)) {
		syslog(LOG_NOTICE, "%s: unsupported TRIM operation", __func__);
		return EOPNOTSUPP;
	}

	return nbd_client_send_request(client, NBD_CMD_TRIM, handle,
				       offset, length, 0, NULL);
}

int
nbd_client_send_disconnect(struct nbd_client *client)
{

	return nbd_client_send_request(client, NBD_CMD_DISCONNECT,
				       (uint64_t)-1, 0, 0, 0, NULL);
}

static inline void
nbd_reply_ntoh(struct nbd_reply *reply)
{

	reply->magic = be32toh(reply->magic);
	reply->error = be32toh(reply->error);
	reply->handle = be64toh(reply->handle);
}

static inline bool
nbd_reply_is_valid(struct nbd_reply *reply)
{

	if (reply->magic != NBD_REPLY_MAGIC) {
		syslog(LOG_ERR, "%s: invalid magic: %#010x (expected %#010x)",
		       __func__, reply->magic, NBD_REPLY_MAGIC);
		return false;
	}

	return true;
}

static inline char const *
nbd_reply_error_string(struct nbd_reply *reply)
{

	switch (reply->error) {

#define CASE_MESSAGE(c) case c: return #c
#define EXTENSION " [unsupported extension]"

		CASE_MESSAGE(NBD_EPERM);
		CASE_MESSAGE(NBD_EIO);
		CASE_MESSAGE(NBD_ENOMEM);
		CASE_MESSAGE(NBD_EINVAL);
		CASE_MESSAGE(NBD_ENOSPC);
		CASE_MESSAGE(NBD_EOVERFLOW) EXTENSION;
		CASE_MESSAGE(NBD_ESHUTDOWN);

#undef EXTENSION
#undef CASE_MESSAGE

	default: return NULL;
	}
}

static inline void
nbd_reply_dump(struct nbd_reply *reply)
{
	char const *error = nbd_reply_error_string(reply);

	syslog(LOG_DEBUG, "\tmagic: %#010x", reply->magic);

	if (error == NULL)
		syslog(LOG_DEBUG, "\terror: [unknown] %#010x (%d)",
		       reply->error, reply->error);
	else
		syslog(LOG_DEBUG, "\terror: %s (%s)",
		       strerror(reply->error), error);

	syslog(LOG_DEBUG, "\thandle: %#018lx", reply->handle);
}

int
nbd_client_recv_reply_header(struct nbd_client *client, uint64_t *handle)
{
	struct nbd_reply reply;
	ssize_t len;

	while (true) {
		len = client->recv(client, &reply, sizeof reply);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len != sizeof reply) {
			syslog(LOG_ERR, "%s: connection failed: %m", __func__);
			return FAILURE;
		}
		break;
	}

	nbd_reply_ntoh(&reply);

	if (!nbd_reply_is_valid(&reply)) {
		syslog(LOG_ERR, "%s: invalid reply", __func__);
		goto bad_reply;
	}

	switch (reply.error) {
	case SUCCESS:
		break;
	case NBD_EINVAL:
		syslog(LOG_WARNING, "%s: server replied invalid command usage",
		       __func__);
		return EINVAL;
	default:
		syslog(LOG_ERR, "%s: request error", __func__);
		goto bad_reply;
	}

	*handle = reply.handle;

	return SUCCESS;

 bad_reply:
	nbd_reply_dump(&reply);
	return FAILURE;
}

int
nbd_client_recv_reply_data(struct nbd_client *client, size_t length,
			   size_t buflen, uint8_t *buf)
{
	size_t recvlen;
	ssize_t len;

	if (length == 0)
		return SUCCESS;

	assert(buflen > 0);
	assert(buf != NULL);

	recvlen = MIN(length, buflen);

	while (true) {
		len = client->recv(client, buf, recvlen);
		if (client->disconnect)
			return FAILURE;
		if (len == -1 && errno == EINTR)
			continue;
		if (len != recvlen) {
			syslog(LOG_ERR, "%s: connection failed: %m", __func__);
			return FAILURE;
		}
		break;
	}

	if (length > buflen)
		return MOREDATA;

	return SUCCESS;
}
