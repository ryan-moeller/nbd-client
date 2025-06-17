/*
 * Copyright (c) 2015-2026 Ryan Moeller
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NBD_CLIENT_H_
#define _NBD_CLIENT_H_

#include <sys/types.h>

#include <libcasper.h>

#include <openssl/ssl.h>

struct addrinfo;

typedef struct nbd_client *nbd_client_t;

nbd_client_t nbd_client_alloc(void);
void nbd_client_init(nbd_client_t client, SSL_CTX *ssl_ctx,
    unsigned sndbuf, unsigned rcvbuf);
void nbd_client_free(nbd_client_t client);

void nbd_client_close(nbd_client_t client);

int nbd_client_rights_limit(nbd_client_t client);

uint64_t nbd_client_get_size(nbd_client_t client);
void nbd_client_get_block_sizes(nbd_client_t client, uint32_t *minbs,
    uint32_t *prefbs, uint32_t *maxpl);

bool nbd_client_get_disconnect(nbd_client_t client);
void nbd_client_set_disconnect(nbd_client_t client, bool disconnect);

void nbd_client_disable_trim(nbd_client_t client);

struct addrinfo *nbd_client_connect(nbd_client_t client, cap_channel_t *capnet,
    const char *host, struct addrinfo *ai);
void nbd_client_shutdown(nbd_client_t client);

/* Callback is responsible for freeing name/description. */
typedef int (*nbd_client_list_cb)(void *ctx, char *name, char *description);

int nbd_client_list(nbd_client_t client, nbd_client_list_cb cb, void *ctx);
int nbd_client_abort(nbd_client_t client);

int nbd_client_negotiate(nbd_client_t client, const char *name);
int nbd_client_send_read(nbd_client_t client, uint64_t handle,
    off_t offset, size_t length);
int nbd_client_send_write(nbd_client_t client, uint64_t handle,
    off_t offset, size_t length, size_t datalen, const uint8_t *data);
int nbd_client_send_flush(nbd_client_t client, uint64_t handle);
int nbd_client_send_trim(nbd_client_t client, uint64_t handle,
    off_t offset, size_t length);
int nbd_client_send_disconnect(nbd_client_t client);
int nbd_client_recv_reply_header(nbd_client_t client, uint64_t *handle);
int nbd_client_recv_reply_data(nbd_client_t client, size_t length,
    size_t buflen, uint8_t *buf);

#endif /* _NBD_CLIENT_H_ */
