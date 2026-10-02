/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

#include "cbl_impl.h"

#define	KiB	(UINT64_C(1) << 10)
#define	MiB	(UINT64_C(1) << 20)
#define	GiB	(UINT64_C(1) << 30)

static const struct {
	uint64_t	def;
	uint64_t	min;
	uint64_t	max;
} cbl_limit_tab[CBL_LIM__COUNT] = {
	[CBL_LIM_MAX_FRAME] =		{ 1 * MiB, 4 * KiB, 64 * MiB },
	[CBL_LIM_MAX_DEPTH] =		{ 16, 1, CBL_DEPTH_HARD_MAX },
	[CBL_LIM_MAX_ATTRS] =		{ 4096, 16, 1024 * 1024 },
	[CBL_LIM_MAX_STREAMS] =		{ 64, 0, 65536 },
	[CBL_LIM_STREAM_WINDOW] =	{ 256 * KiB, 0, INT32_MAX },
	[CBL_LIM_MAX_INFLIGHT] =	{ 256, 1, 65536 },
	[CBL_LIM_SENDQ_BYTES] =		{ 8 * MiB, 64 * KiB, 1 * GiB },
	[CBL_LIM_MAX_CONNS] =		{ 1024, 1, 1024 * 1024 },
	[CBL_LIM_HANDSHAKE_MS] =	{ 10000, 1, 3600000 },
	[CBL_LIM_IDLE_MS] =		{ 300000, 0, UINT32_MAX },
	[CBL_LIM_STREAM_CLOSE_MS] =	{ 10000, 1, 3600000 },
	[CBL_LIM_REQUEST_MS] =		{ 30000, 1, UINT32_MAX },
};

void
cbl_limits_default(struct cbl_limits *lim)
{

	for (int i = 0; i < CBL_LIM__COUNT; i++)
		lim->v[i] = cbl_limit_tab[i].def;
}

int
cbl_limit_check(enum cbl_limit l, uint64_t v)
{

	if ((unsigned)l >= CBL_LIM__COUNT)
		return (EINVAL);
	if (v < cbl_limit_tab[l].min || v > cbl_limit_tab[l].max)
		return (EINVAL);
	return (0);
}

const char *
cbl_version(void)
{

	return ("0.1.0");
}

int
cbl_ctx_new(cbl_ctx **ctxp)
{
	cbl_ctx *ctx;
	int error;

	if (ctxp == NULL)
		return (EINVAL);
	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return (ENOMEM);
	error = pthread_mutex_init(&ctx->mtx, NULL);
	if (error != 0) {
		free(ctx);
		return (error);
	}
	if ((error = pthread_rwlock_init(&ctx->famlock, NULL)) != 0) {
		pthread_mutex_destroy(&ctx->mtx);
		free(ctx);
		return (error);
	}
	pthread_cond_init(&ctx->famcv, NULL);
	pthread_mutex_init(&ctx->submtx, NULL);
	RB_INIT(&ctx->groups);
	RB_INIT(&ctx->fams);
	ctx->next_fam = 1;
	ctx->next_group = CBL_CTRL_GROUP_NOTIFY + 1;
	cbl_limits_default(&ctx->lim);
	if ((error = cbl_ctrl_register(ctx)) != 0) {
		cbl_ctx_free(ctx);
		return (error);
	}
	*ctxp = ctx;
	return (0);
}

/*
 * Free a context nothing uses any more: EBUSY while a loop, listener or
 * connection made from it still exists (freeing it would pull their
 * configuration from under them).
 */
int
cbl_ctx_free(cbl_ctx *ctx)
{

	if (ctx == NULL)
		return (0);
	if (atomic_load(&ctx->nobjs) != 0)
		return (EBUSY);
	cbl_family_free_all(ctx);
	cbl_tls_free(ctx->tls);
	pthread_mutex_destroy(&ctx->submtx);
	pthread_cond_destroy(&ctx->famcv);
	pthread_rwlock_destroy(&ctx->famlock);
	pthread_mutex_destroy(&ctx->mtx);
	free(ctx);
	return (0);
}

int
cbl_ctx_set_limit(cbl_ctx *ctx, enum cbl_limit l, uint64_t v)
{
	int error;

	if (ctx == NULL)
		return (EINVAL);
	if ((error = cbl_limit_check(l, v)) != 0)
		return (error);
	pthread_mutex_lock(&ctx->mtx);
	if (ctx->frozen)
		error = EBUSY;
	else
		ctx->lim.v[l] = v;
	pthread_mutex_unlock(&ctx->mtx);
	return (error);
}

int
cbl_ctx_get_limit(cbl_ctx *ctx, enum cbl_limit l, uint64_t *vp)
{

	if (ctx == NULL || vp == NULL || (unsigned)l >= CBL_LIM__COUNT)
		return (EINVAL);
	pthread_mutex_lock(&ctx->mtx);
	*vp = ctx->lim.v[l];
	pthread_mutex_unlock(&ctx->mtx);
	return (0);
}

/* Default TLS configuration for listeners and connections. */
int
cbl_ctx_set_tls(cbl_ctx *ctx, cbl_tls *tls)
{
	cbl_tls *old;

	if (ctx == NULL)
		return (EINVAL);
	pthread_mutex_lock(&ctx->mtx);
	if (ctx->frozen) {
		pthread_mutex_unlock(&ctx->mtx);
		return (EBUSY);
	}
	if (tls != NULL)
		cbl_tls_ref(tls);
	old = ctx->tls;
	ctx->tls = tls;
	pthread_mutex_unlock(&ctx->mtx);
	cbl_tls_free(old);
	return (0);
}
