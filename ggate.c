/*
 * Copyright (c) 2016-2025 Ryan Moeller
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <geom/gate/g_gate.h>

#include "check.h"
#include "ggate.h"

int
ggate_load_module(void)
{

	if (modfind("g_gate") != FAILURE)
		return SUCCESS;

	if (kldload("geom_gate") == FAILURE
	    || modfind("g_gate") == FAILURE) {
		if (errno != EEXIST) {
			syslog(LOG_ERR,
			       "%s: failed to load geom_gate module: %m",
			       __func__);
			return FAILURE;
		}
	}

	return SUCCESS;
}

struct ggate_context {
	int ctl;
	int unit;
};

struct ggate_context *
ggate_context_alloc(void)
{
	struct ggate_context *ctx;

	ctx = (struct ggate_context *)malloc(sizeof (struct ggate_context));
	if (ctx == NULL) {
		assert(errno == ENOMEM);
		syslog(LOG_ERR, "%s: failed to allocate ggate context: %m",
		       __func__);
	}

	return ctx;
}

void
ggate_context_init(struct ggate_context *ctx)
{

	ctx->ctl = -1;
	ctx->unit = G_GATE_UNIT_AUTO;
}

void
ggate_context_free(struct ggate_context *ctx)
{

	free(ctx);
}

int
ggate_context_open(struct ggate_context *ctx)
{
	int fd;

	fd = open("/dev/" G_GATE_CTL_NAME, O_RDWR);
	if (fd == FAILURE) {
		syslog(LOG_ERR,
		       "%s: failed to open control device (/dev/%s): %m",
		       __func__, G_GATE_CTL_NAME);
		return FAILURE;
	}

	ctx->ctl = fd;

	return SUCCESS;
}

void
ggate_context_close(struct ggate_context *ctx)
{

	close(ctx->ctl);
	ctx->ctl = -1;
}

int
ggate_context_rights_limit(struct ggate_context *ctx)
{
	unsigned long const cmds[] = {
		G_GATE_CMD_CREATE, G_GATE_CMD_DESTROY,
		G_GATE_CMD_START, G_GATE_CMD_DONE, G_GATE_CMD_CANCEL,
	};
	cap_rights_t rights;
	int ctl;

	ctl = ctx->ctl;

	if (cap_rights_limit(ctl, cap_rights_init(&rights, CAP_IOCTL))
	    == FAILURE) {
		syslog(LOG_ERR,
		       "%s: failed to limit capabilities (/dev/%s): %m",
		       __func__, G_GATE_CTL_NAME);
		return FAILURE;
	}

	if (cap_ioctls_limit(ctl, cmds, nitems(cmds)) == FAILURE) {
		syslog(LOG_ERR, "%s: failed to limit ioctls (/dev/%s): %m",
		       __func__, G_GATE_CTL_NAME);
		return FAILURE;
	}

	return SUCCESS;
}

int
ggate_context_get_unit(struct ggate_context *ctx)
{

	return ctx->unit;
}

int
ggate_context_ioctl(struct ggate_context *ctx, uint64_t req, void *data)
{
	int error;

	while (ioctl(ctx->ctl, req, data) == FAILURE) {
		if (errno == EINTR)
			continue;

		syslog(LOG_ERR, "%s: ioctl failed (/dev/%s): %m",
		       __func__, G_GATE_CTL_NAME);

		return FAILURE;
	}

	return SUCCESS;
}

static inline void
g_gate_ctl_create_dump(struct g_gate_ctl_create *ggioc)
{

	syslog(LOG_DEBUG, "\tgctl_version: %u", ggioc->gctl_version);
	syslog(LOG_DEBUG, "\tgctl_mediasize: %ld", ggioc->gctl_mediasize);
	syslog(LOG_DEBUG, "\tgctl_sectorsize: %u", ggioc->gctl_sectorsize);
	syslog(LOG_DEBUG, "\tgctl_flags: %#010x", ggioc->gctl_flags);
	syslog(LOG_DEBUG, "\tgctl_maxcount: %u", ggioc->gctl_maxcount);
	syslog(LOG_DEBUG, "\tgctl_timeout: %u", ggioc->gctl_timeout);
	syslog(LOG_DEBUG, "\tgctl_name: %.*s", NAME_MAX, ggioc->gctl_name);
	syslog(LOG_DEBUG, "\tgctl_info: %.*s", G_GATE_INFOSIZE, ggioc->gctl_info);
	syslog(LOG_DEBUG, "\tgctl_readprov: %.*s", NAME_MAX, ggioc->gctl_readprov);
	syslog(LOG_DEBUG, "\tgctl_readoffset: %ld", ggioc->gctl_readoffset);
	syslog(LOG_DEBUG, "\tgctl_unit: %d", ggioc->gctl_unit);
}

static int
limit_create_ioctl(struct ggate_context *ctx)
{
	unsigned long const cmds[] = {
		G_GATE_CMD_DESTROY, G_GATE_CMD_CANCEL,
		G_GATE_CMD_START, G_GATE_CMD_DONE,
	};

	if (cap_ioctls_limit(ctx->ctl, cmds, nitems(cmds)) == FAILURE) {
		syslog(LOG_ERR, "%s: failed to limit ioctls (/dev/%s): %m",
		       __func__, G_GATE_CTL_NAME);
		return FAILURE;
	}

	return SUCCESS;
}

int
ggate_context_create_device(struct ggate_context *ctx, char const *info,
			    off_t mediasize, uint32_t sectorsize,
			    uint32_t flags)
{
	struct g_gate_ctl_create ggioc;
	int unit;

	unit = ctx->unit;

	ggioc = (struct g_gate_ctl_create){
		.gctl_version = G_GATE_VERSION,
		.gctl_mediasize = mediasize,
		.gctl_sectorsize = sectorsize,
		.gctl_flags = flags,
		.gctl_maxcount = GGATE_DEFAULT_QUEUE_SIZE,
		.gctl_timeout = GGATE_DEFAULT_TIMEOUT,
		.gctl_unit = unit,
	};

	if (strlcpy(ggioc.gctl_info, info, sizeof ggioc.gctl_info)
	    >= sizeof ggioc.gctl_info)
		return FAILURE;

	if (ggate_context_ioctl(ctx, G_GATE_CMD_CREATE, &ggioc) == FAILURE) {
		syslog(LOG_ERR, "%s: failed to create ggate device", __func__);
		g_gate_ctl_create_dump(&ggioc);
		return FAILURE;
	}

	if (limit_create_ioctl(ctx) == FAILURE)
		return FAILURE;

	if (unit == G_GATE_UNIT_AUTO) {
		printf("%s%u\n", G_GATE_PROVIDER_NAME, ggioc.gctl_unit);
		fflush(stdout);
	}

	ctx->unit = ggioc.gctl_unit;

	return SUCCESS;
}

int
ggate_context_destroy_device(struct ggate_context *ctx, bool force)
{
	struct g_gate_ctl_destroy ggioc;

	ggioc = (struct g_gate_ctl_destroy){
		.gctl_version = G_GATE_VERSION,
		.gctl_unit = ctx->unit,
		.gctl_force = force ? 1 : 0,
	};

	if (ggate_context_ioctl(ctx, G_GATE_CMD_DESTROY, &ggioc) == FAILURE) {
		syslog(LOG_ERR, "%s: failed to destroy ggate device", __func__);
		return FAILURE;
	}

	ctx->unit = G_GATE_UNIT_AUTO;

	return SUCCESS;
}

int
ggate_context_cancel(struct ggate_context *ctx, uintptr_t seq)
{
	struct g_gate_ctl_cancel ggioc;

	ggioc = (struct g_gate_ctl_cancel){
		.gctl_version = G_GATE_VERSION,
		.gctl_unit = ctx->unit,
		.gctl_seq = seq,
	};

	if (ggate_context_ioctl(ctx, G_GATE_CMD_CANCEL, &ggioc) == FAILURE) {
		syslog(LOG_ERR, "%s: failed to cancel ggate command %lx",
		       __func__, seq);
		return FAILURE;
	}

	return SUCCESS;
}
