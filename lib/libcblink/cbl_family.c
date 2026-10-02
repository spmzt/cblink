/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Family registry (the generic netlink equivalent).  Ids are assigned
 * dynamically per context; id 0 is the built-in control family.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_impl.h"

static int
fam_cmp(struct cbl_family *a, struct cbl_family *b)
{

	return ((a->id > b->id) - (a->id < b->id));
}

RB_GENERATE_STATIC(cbl_fam_tree, cbl_family, link, fam_cmp);

static bool
name_valid(const char *name, bool builtin)
{
	size_t len;

	if (name == NULL)
		return (false);
	len = strlen(name);
	if (len == 0 || len > CBL_FAMILY_NAME_MAX)
		return (false);
	if (name[0] < 'a' || name[0] > 'z')
		return (false);
	for (size_t i = 1; i < len; i++) {
		char c = name[i];

		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		    c == '_' || c == '.' || c == '-'))
			return (false);
	}
	if (!builtin && (strcmp(name, "ctrl") == 0 ||
	    strncmp(name, "cblink.", 7) == 0))
		return (false);
	return (true);
}

static int
def_check(const struct cbl_family_def *def, bool builtin)
{
	const struct cbl_op *op;

	if (def == NULL || def->abi != CBL_FAMILY_ABI)
		return (EINVAL);
	if (!name_valid(def->name, builtin) || def->version == 0)
		return (EINVAL);
	if (def->nops > 0 && def->ops == NULL)
		return (EINVAL);
	if (def->nmcgrps > 0 && def->mcgrps == NULL)
		return (EINVAL);
	for (uint32_t i = 0; i < def->nops; i++) {
		op = &def->ops[i];
		if (op->cmd == 0 || (i > 0 && op->cmd <= def->ops[i - 1].cmd))
			return (EINVAL);
		if ((op->flags & ~(CBL_OPF_DO | CBL_OPF_DUMP | CBL_OPF_STREAM |
		    CBL_OPF_PUSH | CBL_OPF_AUTH)) != 0)
			return (EINVAL);
		if (((op->flags & CBL_OPF_DO) != 0) != (op->doit != NULL))
			return (EINVAL);
		if (((op->flags & CBL_OPF_DUMP) != 0) != (op->dumpit != NULL))
			return (EINVAL);
		if (((op->flags & (CBL_OPF_STREAM | CBL_OPF_PUSH)) != 0) !=
		    (op->stream_open != NULL))
			return (EINVAL);
		if ((op->flags & CBL_OPF_STREAM) != 0 &&
		    (op->flags & CBL_OPF_PUSH) != 0)
			return (EINVAL);
		if ((op->flags & (CBL_OPF_DO | CBL_OPF_DUMP | CBL_OPF_STREAM |
		    CBL_OPF_PUSH)) == 0)
			return (EINVAL);
		if (cbl_policy_set_check(op->policy) != 0)
			return (EINVAL);
	}
	for (uint32_t i = 0; i < def->nmcgrps; i++) {
		if (!name_valid(def->mcgrps[i].name, true))
			return (EINVAL);
		for (uint32_t j = 0; j < i; j++)
			if (strcmp(def->mcgrps[i].name,
			    def->mcgrps[j].name) == 0)
				return (EINVAL);
	}
	return (0);
}

static int
fam_insert(cbl_ctx *ctx, const struct cbl_family_def *def, void *arg,
    bool builtin, cbl_family **famp)
{
	struct cbl_family key, *fam, *f;
	uint32_t id;
	int error;

	if ((error = def_check(def, builtin)) != 0)
		return (error);
	if ((fam = calloc(1, sizeof(*fam))) == NULL)
		return (ENOMEM);
	fam->ctx = ctx;
	fam->def = def;
	fam->arg = arg;
	atomic_init(&fam->refs, 1);

	pthread_rwlock_wrlock(&ctx->famlock);
	RB_FOREACH(f, cbl_fam_tree, &ctx->fams) {
		if (strcmp(f->def->name, def->name) == 0) {
			pthread_rwlock_unlock(&ctx->famlock);
			free(fam);
			return (EEXIST);
		}
	}
	if (builtin)
		id = 0;
	else {
		/* Next unused id in 1..65535. */
		for (uint32_t n = 0;; n++) {
			if (n == 65535) {
				pthread_rwlock_unlock(&ctx->famlock);
				free(fam);
				return (ENOSPC);
			}
			id = ctx->next_fam;
			ctx->next_fam = ctx->next_fam == 65535 ? 1 :
			    ctx->next_fam + 1;
			key.id = (uint16_t)id;
			if (RB_FIND(cbl_fam_tree, &ctx->fams, &key) == NULL)
				break;
		}
	}
	if (def->nmcgrps > 0) {
		if (UINT32_MAX - ctx->next_group < def->nmcgrps) {
			pthread_rwlock_unlock(&ctx->famlock);
			free(fam);
			return (ENOSPC);
		}
		fam->group_base = ctx->next_group;
		ctx->next_group += def->nmcgrps;
	}
	fam->id = (uint16_t)id;
	RB_INSERT(cbl_fam_tree, &ctx->fams, fam);
	pthread_rwlock_unlock(&ctx->famlock);
	if (famp != NULL)
		*famp = fam;
	return (0);
}

int
cbl_family_register(cbl_ctx *ctx, const struct cbl_family_def *def,
    void *arg, cbl_family **famp)
{

	cbl_family *fam;
	int error;

	if (ctx == NULL)
		return (EINVAL);
	if ((error = fam_insert(ctx, def, arg, false, &fam)) != 0)
		return (error);
	cbl_ctrl_notify_family(ctx, fam, true);
	if (famp != NULL)
		*famp = fam;
	return (0);
}

/* The control family: fixed id 0, fixed group 1 ("notify"). */
int
cbl_ctx_add_builtin(cbl_ctx *ctx, const struct cbl_family_def *def,
    void *arg)
{
	uint32_t saved = ctx->next_group;
	int error;

	ctx->next_group = CBL_CTRL_GROUP_NOTIFY;
	error = fam_insert(ctx, def, arg, true, &ctx->ctrl);
	ctx->next_group = saved > ctx->next_group ? saved : ctx->next_group;
	return (error);
}

cbl_family *
cbl_family_lookup(cbl_ctx *ctx, uint16_t id)
{
	struct cbl_family key, *fam;

	key.id = id;
	pthread_rwlock_rdlock(&ctx->famlock);
	fam = RB_FIND(cbl_fam_tree, &ctx->fams, &key);
	if (fam != NULL && !fam->dead)
		atomic_fetch_add(&fam->refs, 1);
	else
		fam = NULL;
	pthread_rwlock_unlock(&ctx->famlock);
	return (fam);
}

cbl_family *
cbl_family_lookup_name(cbl_ctx *ctx, const char *name)
{
	struct cbl_family *fam, *found = NULL;

	pthread_rwlock_rdlock(&ctx->famlock);
	RB_FOREACH(fam, cbl_fam_tree, &ctx->fams) {
		if (!fam->dead && strcmp(fam->def->name, name) == 0) {
			atomic_fetch_add(&fam->refs, 1);
			found = fam;
			break;
		}
	}
	pthread_rwlock_unlock(&ctx->famlock);
	return (found);
}

/* Iterate families in id order: the first with id >= "from". */
cbl_family *
cbl_family_next(cbl_ctx *ctx, uint32_t from)
{
	struct cbl_family key, *fam;

	if (from > 65535)
		return (NULL);
	key.id = (uint16_t)from;
	pthread_rwlock_rdlock(&ctx->famlock);
	fam = RB_NFIND(cbl_fam_tree, &ctx->fams, &key);
	while (fam != NULL && fam->dead)
		fam = RB_NEXT(cbl_fam_tree, &ctx->fams, fam);
	if (fam != NULL)
		atomic_fetch_add(&fam->refs, 1);
	pthread_rwlock_unlock(&ctx->famlock);
	return (fam);
}

void
cbl_family_rele(cbl_family *fam)
{
	cbl_ctx *ctx = fam->ctx;

	if (atomic_fetch_sub(&fam->refs, 1) == 1) {
		free(fam);
		return;
	}
	/*
	 * Only cbl_family_unregister() waits, for the count to drop to its
	 * own reference.  Both sides use sequentially consistent atomics:
	 * either it sees our decrement, or we see it waiting and wake it.
	 * "fam" is not ours any more: the waiter may free it at once.
	 */
	if (atomic_load(&ctx->fam_waiters) != 0) {
		pthread_mutex_lock(&ctx->mtx);
		pthread_cond_broadcast(&ctx->famcv);
		pthread_mutex_unlock(&ctx->mtx);
	}
}

/*
 * Remove a family.  Returns once no handler of the family is running, so
 * the caller may then free the handlers' argument.  Must not be called
 * from one of the family's own handlers.
 */
int
cbl_family_unregister(cbl_family *fam)
{
	cbl_ctx *ctx;

	if (fam == NULL || fam->id == CBL_CTRL_FAMILY)
		return (EINVAL);
	ctx = fam->ctx;
	pthread_rwlock_wrlock(&ctx->famlock);
	if (fam->dead) {
		pthread_rwlock_unlock(&ctx->famlock);
		return (ENOENT);
	}
	fam->dead = true;
	RB_REMOVE(cbl_fam_tree, &ctx->fams, fam);
	pthread_rwlock_unlock(&ctx->famlock);
	cbl_ctrl_notify_family(ctx, fam, false);
	pthread_mutex_lock(&ctx->mtx);
	atomic_fetch_add(&ctx->fam_waiters, 1);
	while (atomic_load(&fam->refs) > 1)
		pthread_cond_wait(&ctx->famcv, &ctx->mtx);
	atomic_fetch_sub(&ctx->fam_waiters, 1);
	pthread_mutex_unlock(&ctx->mtx);
	cbl_family_rele(fam);
	return (0);
}

/* Drop every family; the context is going away. */
void
cbl_family_free_all(cbl_ctx *ctx)
{
	struct cbl_family *fam;

	while ((fam = RB_MIN(cbl_fam_tree, &ctx->fams)) != NULL) {
		RB_REMOVE(cbl_fam_tree, &ctx->fams, fam);
		cbl_family_rele(fam);
	}
	ctx->ctrl = NULL;
}

uint16_t
cbl_family_id(const cbl_family *fam)
{

	return (fam != NULL ? fam->id : 0);
}

uint32_t
cbl_family_group_id(const cbl_family *fam, uint32_t idx)
{

	if (fam == NULL || idx >= fam->def->nmcgrps)
		return (0);
	return (fam->group_base + idx);
}

static int
op_cmp(const void *key, const void *elem)
{
	uint16_t cmd = *(const uint16_t *)key;
	const struct cbl_op *op = elem;

	return ((cmd > op->cmd) - (cmd < op->cmd));
}

const struct cbl_op *
cbl_family_op(const cbl_family *fam, uint16_t cmd)
{

	if (fam->def->nops == 0)
		return (NULL);
	return (bsearch(&cmd, fam->def->ops, fam->def->nops,
	    sizeof(*fam->def->ops), op_cmp));
}
