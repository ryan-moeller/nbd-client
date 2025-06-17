/*
 * Copyright (c) 2025 Ryan Moeller
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _GGIO_H_
#define _GGIO_H_

#include <sys/queue.h>
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include <geom/gate/g_gate.h>

struct ggio {
	struct g_gate_ctl_io io;
	TAILQ_ENTRY(ggio) link;
};

struct ggioq {
	TAILQ_HEAD(, ggio) head;
	pthread_mutex_t lock;
	pthread_cond_t cond;
};

static inline void
ggioq_init(struct ggioq *ggioq)
{
	TAILQ_INIT(&ggioq->head);
	pthread_mutex_init(&ggioq->lock, NULL);
	pthread_cond_init(&ggioq->cond, NULL);
}

static inline bool
ggioq_empty(struct ggioq *ggioq)
{
	bool empty;

	pthread_mutex_lock(&ggioq->lock);
	empty = TAILQ_EMPTY(&ggioq->head);
	pthread_mutex_unlock(&ggioq->lock);
	return (empty);
}

static inline void
ggioq_destroy(struct ggioq *ggioq)
{
	assert(TAILQ_EMPTY(&ggioq->head));
	pthread_mutex_destroy(&ggioq->lock);
	pthread_cond_destroy(&ggioq->cond);
}

static inline void
ggioq_enqueue(struct ggioq *ggioq, struct ggio *ggio)
{
	pthread_mutex_lock(&ggioq->lock);
	if (TAILQ_EMPTY(&ggioq->head))
		pthread_cond_signal(&ggioq->cond);
	TAILQ_INSERT_TAIL(&ggioq->head, ggio, link);
	pthread_mutex_unlock(&ggioq->lock);
}

static inline struct ggio *
ggioq_dequeue(struct ggioq *ggioq, _Atomic(bool) *bail)
{
	struct ggio *ggio;

	pthread_mutex_lock(&ggioq->lock);
	while ((ggio = TAILQ_FIRST(&ggioq->head)) == NULL && !atomic_load(bail))
		pthread_cond_wait(&ggioq->cond, &ggioq->lock);
	if (ggio != NULL)
		TAILQ_REMOVE(&ggioq->head, ggio, link);
	pthread_mutex_unlock(&ggioq->lock);
	return (ggio);
}

static inline struct ggio *
ggioq_takefirst(struct ggioq *ggioq)
{
	struct ggio *ggio;

	ggio = TAILQ_FIRST(&ggioq->head);
	if (ggio != NULL)
		TAILQ_REMOVE(&ggioq->head, ggio, link);
	return (ggio);
}

static inline void
ggioq_remove(struct ggioq *ggioq, struct ggio *ggio)
{
	pthread_mutex_lock(&ggioq->lock);
	TAILQ_REMOVE(&ggioq->head, ggio, link);
	pthread_mutex_unlock(&ggioq->lock);
}

static inline struct ggio *
ggioq_find(struct ggioq *ggioq, uint64_t handle)
{
	struct ggio *ggio;

	pthread_mutex_lock(&ggioq->lock);
	TAILQ_FOREACH(ggio, &ggioq->head, link) {
		if (ggio->io.gctl_seq == handle)
			break;
	}
	if (ggio != NULL)
		TAILQ_REMOVE(&ggioq->head, ggio, link);
	pthread_mutex_unlock(&ggioq->lock);
	return (ggio);
}

#endif /* #ifndef _GGIO_H_ */
