/*
 * Copyright (c) 2016-2025 Ryan Moeller
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _GGATE_H_
#define _GGATE_H_

#include <stdbool.h>
#include <unistd.h>

enum {
	GGATE_DEFAULT_TIMEOUT = 0,
	GGATE_DEFAULT_QUEUE_SIZE = 1024,
};

typedef struct ggate_context *ggate_context_t;

int ggate_load_module();

ggate_context_t ggate_context_alloc();
void ggate_context_init(ggate_context_t ctx);
void ggate_context_free(ggate_context_t ctx);

int ggate_context_open(ggate_context_t ctx);
void ggate_context_close(ggate_context_t ctx);

int ggate_context_rights_limit(ggate_context_t ctx);

int ggate_context_get_unit(ggate_context_t ctx);

int ggate_context_ioctl(ggate_context_t ctx, uint64_t req, void *data);

int ggate_context_create_device(ggate_context_t ctx, char const *host,
				char const *port, char const *path,
				off_t mediasize, uint32_t sectorsize,
				uint32_t flags);
int ggate_context_destroy_device(ggate_context_t ctx, bool force);
int ggate_context_cancel(ggate_context_t ctx, uintptr_t seq);

#endif /* #ifndef _GGATE_H_ */
