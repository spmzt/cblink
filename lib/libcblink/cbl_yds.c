/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Family 1's datastores (RFC 8342), where a program asks for them
 * (cbl_ydatastores()).
 *
 * running is what the handlers keep: their get handlers read, their
 * config true nodes alone.  candidate is one tree, every session's (RFC
 * 6241 section 8.3): made from running at its first EDIT, changed by an
 * EDIT of it a top-level node at a time (the node replaced, as an EDIT
 * of running does), read by a GET of it, put in use by commit, which
 * changes through the handlers every top-level node it has otherwise
 * than running, all or nothing; discard-changes forgets it.
 *
 * A confirmed commit (section 8.4) keeps what each node it changed was
 * before; a thread of its own undoes it at its confirm-timeout, a commit
 * confirms it (its session's, or with persist one that gives the
 * persist-id), cancel-commit undoes it at once, its session going
 * without persist undoes it too.  An undo a handler fails is told to
 * the program's undo_failed (which may try again, raise an alarm, say
 * so); the others go on.
 *
 * NACM's write checks are a commit's as they are an EDIT's, each node it
 * changes; a GET of a datastore leaves out what the user may not read.
 */

#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cbl_data.h"
#include "cbl_dimpl.h"
#include "cbl_impl.h"
#include "cbl_schema.h"
#include "cbl_yimpl.h"
#include "cbl_ymod.h"

/* A top-level node as it was before a confirmed commit changed it. */
struct saved {
	uint64_t	 sid;
	uint8_t		*p;		/* NULL: it was not there */
	size_t		 len;
};

struct cbl_yds {
	cbl_ctx		*ctx;
	unsigned	 flags;
	cbl_yundo_f	*undo_failed;
	void		*arg;
	pthread_mutex_t	 lock;		/* a commit at a time */
	pthread_cond_t	 cv;
	cbl_dtree	*cand;		/* NULL: the same as running */
	/* A confirmed commit waiting for its confirmation. */
	bool		 pending;
	struct timespec	 deadline;
	char		*persist;	/* its persist-id; NULL: by its session */
	cbl_conn	*by;		/* its session, compared alone */
	struct saved	*saved;
	size_t		 nsaved;
	pthread_t	 timer;
	bool		 stopping;
};

/* RFC 6241's default confirm-timeout, seconds. */
#define	CONFIRM_TIMEOUT	600

/* len bytes of p after *b's *len (*cap of it), malloc'd. */
static int
grow(uint8_t **b, size_t *len, size_t *cap, const void *p, size_t n)
{
	uint8_t	*nb;
	size_t	 nc;

	if (*len + n > *cap) {
		nc = MAX(*cap * 2, *len + n + 64);
		if ((nb = realloc(*b, nc)) == NULL)
			return (ENOMEM);
		*b = nb;
		*cap = nc;
	}
	memcpy(*b + *len, p, n);
	*len += n;
	return (0);
}

/*
 * Top-level node n's YANG-CBOR in tree t, as a member of its module's
 * data is (cbl_yencode_member()), malloc'd: a container's or leaf's
 * value, a list's entries in an array.  *pp NULL: none there.
 */
static int
top_bytes(const cbl_dtree *t, const struct cbl_ynode *n, uint8_t **pp,
    size_t *lenp)
{
	struct cbl_ybuf e = { NULL, 0, 0 };
	const cbl_dnode *c;
	size_t count = 0, len = 0, cap = 0;
	uint8_t head[9], *b = NULL;
	int error = 0;

	*pp = NULL;
	*lenp = 0;
	for (c = t != NULL ? cbl_dnode_first(cbl_dtree_root(t)) : NULL;
	    c != NULL; c = cbl_dnode_next(c))
		if (cbl_dnode_schema(c) == n)
			count++;
	if (count == 0)
		return (0);
	if (n->kind == CBL_YN_LIST || n->kind == CBL_YN_LEAFLIST) {
		if (count < 24) {
			head[0] = (uint8_t)(0x80 | count);
			error = grow(&b, &len, &cap, head, 1);
		} else {
			head[0] = 0x9b;
			for (int i = 0; i < 8; i++)
				head[1 + i] = (uint8_t)((uint64_t)count >>
				    (56 - 8 * i));
			error = grow(&b, &len, &cap, head, 9);
		}
	}
	for (c = cbl_dnode_first(cbl_dtree_root(t)); error == 0 && c != NULL;
	    c = cbl_dnode_next(c)) {
		if (cbl_dnode_schema(c) != n)
			continue;
		if ((error = cbl_dnode_encode(c, &e)) == 0)
			error = grow(&b, &len, &cap, e.p, e.len);
		cbl_ybuf_free(&e);
		memset(&e, 0, sizeof(e));
	}
	if (error != 0) {
		free(b);
		return (error);
	}
	*pp = b;
	*lenp = len;
	return (0);
}

/* State taken out of n's subtree: running and candidate are config. */
static void
prune_state(cbl_dnode *n)
{
	cbl_dnode *c, *next;

	for (c = cbl_dnode_first(n); c != NULL; c = next) {
		next = cbl_dnode_next(c);
		if ((cbl_dnode_schema(c)->flags & CBL_YNF_CONFIG) == 0)
			(void)cbl_dnode_remove(c);
		else
			prune_state(c);
	}
}

/* The top-level configuration nodes the servers read and, with edit,
 * change; by SID. */
static int
config_sids(cbl_ctx *ctx, bool edit, uint64_t **vp, size_t *np)
{
	uint64_t *v = NULL;
	size_t n = 0, cap = 0;

	*vp = NULL;
	*np = 0;
	pthread_rwlock_rdlock(&ctx->famlock);
	for (size_t i = 0; i < ctx->nysrv; i++) {
		const struct cbl_yserver *s = ctx->ysrv[i].srv;

		for (uint32_t j = 0; j < s->nhandler; j++) {
			const struct cbl_yhandler *h = &s->handler[j];
			const struct cbl_ynode *nd = cbl_yschema_node(s->schema,
			    h->sid);
			uint64_t *nv;

			if (nd == NULL || !cbl_yis_top_data(nd) ||
			    (nd->flags & CBL_YNF_CONFIG) == 0 ||
			    h->get == NULL || (edit && h->edit == NULL))
				continue;
			if (n == cap) {
				cap = cap * 2 + 16;
				if ((nv = reallocarray(v, cap, sizeof(*v))) ==
				    NULL) {
					pthread_rwlock_unlock(&ctx->famlock);
					free(v);
					return (ENOMEM);
				}
				v = nv;
			}
			v[n++] = h->sid;
		}
	}
	pthread_rwlock_unlock(&ctx->famlock);
	*vp = v;
	*np = n;
	return (0);
}

/* running as a tree, *tp: the configuration nodes the handlers read,
 * read for running. */
int
cbl_yds_running(cbl_req *req, cbl_dtree **tp)
{
	cbl_ctx *ctx = req->conn != NULL ? req->conn->ctx : NULL;
	uint64_t *v;
	size_t n;
	int error;
	bool was;

	*tp = NULL;
	if (ctx == NULL || (error = config_sids(ctx, false, &v, &n)) != 0)
		return (ctx == NULL ? EINVAL : error);
	was = req->yds_running;
	req->yds_running = true;
	error = n > 0 ? cbl_yread_tree(req, v, n, tp, NULL) : 0;
	req->yds_running = was;
	free(v);
	if (error != 0)
		return (error);
	if (*tp == NULL) {
		pthread_rwlock_rdlock(&ctx->famlock);
		*tp = ctx->nysrv > 0 ? cbl_dtree_new(ctx->ysrv[0].srv->schema) :
		    NULL;
		pthread_rwlock_unlock(&ctx->famlock);
		return (*tp != NULL ? 0 : ENOMEM);
	}
	prune_state(cbl_dtree_root(*tp));
	return (0);
}

/* A copy of tree t. */
static cbl_dtree *
tree_copy(const cbl_dtree *t)
{
	struct cbl_ybuf b = { NULL, 0, 0 };
	cbl_dtree *c;
	char why[128];

	if ((c = cbl_dtree_new(cbl_dtree_schema(t))) == NULL)
		return (NULL);
	if (cbl_dtree_encode(t, &b) != 0 || cbl_dtree_decode(c, b.p, b.len, 0,
	    why, sizeof(why)) != 0) {
		cbl_ybuf_free(&b);
		cbl_dtree_free(c);
		return (NULL);
	}
	cbl_ybuf_free(&b);
	return (c);
}

/* The module's data struct of n, its value p (len bytes; NULL: none),
 * in a. */
static void *
struct_of(const struct cbl_ynode *n, const uint8_t *p, size_t len,
    cbl_yarena *a, char *why, size_t whylen, int *errorp)
{
	void *data;

	*errorp = 0;
	if ((data = cbl_yarena_alloc(a, n->module->size)) == NULL) {
		*errorp = ENOMEM;
		return (NULL);
	}
	if (p != NULL && (*errorp = cbl_ydecode_member(n, p, len, data, a,
	    CBL_YD_STRICT, why, whylen)) != 0)
		return (NULL);
	return (data);
}

int
cbl_ydatastores(cbl_ctx *ctx, unsigned flags, cbl_yundo_f *undo_failed,
    void *arg)
{
	struct cbl_yds *d;

	if (ctx == NULL || (flags & ~CBL_YDS_CONFIRMED) != 0)
		return (EINVAL);
	if (ctx->yds != NULL)
		return (EEXIST);
	if ((d = calloc(1, sizeof(*d))) == NULL)
		return (ENOMEM);
	d->ctx = ctx;
	d->flags = flags;
	d->undo_failed = undo_failed;
	d->arg = arg;
	pthread_mutex_init(&d->lock, NULL);
	pthread_cond_init(&d->cv, NULL);
	ctx->yds = d;
	return (0);
}

/* Top-level node n's configuration in data, a get handler's read,
 * as running has it (its state left out): the struct, in a. */
static void *
config_of(const struct cbl_yfound *f, const void *data, cbl_yarena *a,
    char *why, size_t whylen, int *errorp)
{
	struct cbl_ybuf b = { NULL, 0, 0 };
	cbl_dtree *t;
	uint8_t *p = NULL;
	size_t len = 0;
	void *c = NULL;

	*errorp = 0;
	if ((t = cbl_dtree_new(f->srv->schema)) == NULL) {
		*errorp = ENOMEM;
		return (NULL);
	}
	if (cbl_ymember_present(f->n, data) &&
	    ((*errorp = cbl_yencode_member(f->n, data, &b)) != 0 ||
	    (*errorp = cbl_dnode_decode(cbl_dtree_root(t), f->n, b.p, b.len,
	    0, why, whylen, NULL)) != 0))
		goto out;
	prune_state(cbl_dtree_root(t));
	if ((*errorp = top_bytes(t, f->n, &p, &len)) == 0)
		c = struct_of(f->n, p, len, a, why, whylen, errorp);
out:
	free(p);
	cbl_ybuf_free(&b);
	cbl_dtree_free(t);
	return (c);
}

/* The saved nodes put back: what a confirmed commit changed, undone.
 * d->lock held. */
static void
rollback(struct cbl_yds *d, cbl_conn *conn)
{
	struct cbl_yfound f;
	struct cbl_req r;
	cbl_yarena *a;
	void *now, *was;
	char why[160];
	int error;

	for (size_t i = d->nsaved; i-- > 0; ) {
		struct saved *s = &d->saved[i];

		memset(&f, 0, sizeof(f));
		memset(&r, 0, sizeof(r));
		r.conn = conn;
		r.recovery = true;
		r.yds_running = true;
		r.yds_undo = true;
		atomic_init(&r.refs, 1);
		why[0] = '\0';
		error = 0;
		if (!cbl_yfind(d->ctx, s->sid, &f) || f.h == NULL ||
		    f.h->edit == NULL || (a = cbl_yarena_new()) == NULL)
			error = ENOENT;
		else {
			r.yarg = f.arg;
			/* Running as it is now, its configuration alone,
			 * as a commit's edit has it. */
			if ((now = struct_of(f.n, NULL, 0, a, why, sizeof(why),
			    &error)) != NULL && (f.h->get == NULL ||
			    (error = f.h->get(&r, now, a)) == 0) &&
			    (now = config_of(&f, now, a, why, sizeof(why),
			    &error)) != NULL &&
			    (was = struct_of(f.n, s->p, s->len, a, why,
			    sizeof(why), &error)) != NULL)
				error = f.h->edit(&r, now, was);
			cbl_yarena_free(a);
			/* The access rules put back: read again. */
			if (strcmp(f.n->module->name, "ietf-netconf-acm") == 0)
				cbl_ynacm_changed(d->ctx);
			/* On-change subscriptions told. */
			cbl_ysub_changed(d->ctx, f.n);
		}
		if (error != 0 && d->undo_failed != NULL)
			d->undo_failed(d->ctx, f.n, error, r.err_msg != NULL ?
			    r.err_msg : why[0] != '\0' ? why : strerror(error),
			    d->arg);
		free(r.err_msg);
		free(r.err_yapptag);
		cbl_yds_req_free(&r);
		/* Stopped there: what is left stays as committed. */
		if (error != 0)
			break;
	}
	for (size_t i = 0; i < d->nsaved; i++)
		free(d->saved[i].p);
	free(d->saved);
	d->saved = NULL;
	d->nsaved = 0;
	d->pending = false;
	free(d->persist);
	d->persist = NULL;
	d->by = NULL;
	pthread_cond_broadcast(&d->cv);
}

bool
cbl_req_yundo(const cbl_req *req)
{

	return (req != NULL && req->yds_undo);
}

enum cbl_yds_name
cbl_req_ydatastore(const cbl_req *req)
{

	return (req != NULL && req->yds_running ? CBL_YDS_RUNNING :
	    CBL_YDS_OPERATIONAL);
}

/* The thread that undoes a confirmed commit at its confirm-timeout. */
static void *
timer_run(void *p)
{
	struct cbl_yds *d = p;
	struct timespec now;

	pthread_mutex_lock(&d->lock);
	while (!d->stopping) {
		if (!d->pending) {
			pthread_cond_wait(&d->cv, &d->lock);
			continue;
		}
		(void)clock_gettime(CLOCK_REALTIME, &now);
		if (now.tv_sec > d->deadline.tv_sec || (now.tv_sec ==
		    d->deadline.tv_sec && now.tv_nsec >= d->deadline.tv_nsec)) {
			rollback(d, NULL);
			continue;
		}
		(void)pthread_cond_timedwait(&d->cv, &d->lock, &d->deadline);
	}
	pthread_mutex_unlock(&d->lock);
	return (NULL);
}

void
cbl_yds_free(cbl_ctx *ctx)
{
	struct cbl_yds *d = ctx->yds;
	bool joined;

	if (d == NULL)
		return;
	pthread_mutex_lock(&d->lock);
	d->stopping = true;
	joined = d->timer != 0;
	pthread_cond_broadcast(&d->cv);
	pthread_mutex_unlock(&d->lock);
	if (joined)
		(void)pthread_join(d->timer, NULL);
	for (size_t i = 0; i < d->nsaved; i++)
		free(d->saved[i].p);
	free(d->saved);
	free(d->persist);
	cbl_dtree_free(d->cand);
	pthread_cond_destroy(&d->cv);
	pthread_mutex_destroy(&d->lock);
	free(d);
	ctx->yds = NULL;
}

void
cbl_yds_conn_closed(cbl_conn *conn)
{
	struct cbl_yds *d = conn->ctx->yds;

	if (d == NULL)
		return;
	pthread_mutex_lock(&d->lock);
	/* Its session gone without persist: undone now, by the thread. */
	if (d->pending && d->persist == NULL && d->by == conn) {
		(void)clock_gettime(CLOCK_REALTIME, &d->deadline);
		d->by = NULL;
		pthread_cond_broadcast(&d->cv);
	}
	pthread_mutex_unlock(&d->lock);
}

bool
cbl_ydatastore_pending(cbl_ctx *ctx, struct timespec *until)
{
	struct cbl_yds *d;
	bool p;

	if (ctx == NULL || (d = ctx->yds) == NULL)
		return (false);
	pthread_mutex_lock(&d->lock);
	if ((p = d->pending) && until != NULL)
		*until = d->deadline;
	pthread_mutex_unlock(&d->lock);
	return (p);
}

int
cbl_yds_of(cbl_req *req, enum cbl_yds_name *ds, bool *said)
{
	struct cblink_datastore s;
	cbl_yarena *a;
	char why[128];
	int error;

	*ds = CBL_YDS_OPERATIONAL;
	*said = false;
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	error = cbl_msg_ydecode(req->msg, cbl_fw_node("datastore"), &s, a,
	    CBL_YD_STRICT, why, sizeof(why));
	cbl_yarena_free(a);
	if (error == ENOENT)
		return (0);
	if (error != 0)
		return (cbl_ysay(req, error, 0, "malformed-message", why));
	if (req->conn->ctx->yds == NULL &&
	    s.name != CBLINK_DATASTORE_NAME_OPERATIONAL)
		return (cbl_ysay(req, EOPNOTSUPP, 0, "operation-not-supported",
		    "no datastores here but the operational state"));
	*said = true;
	*ds = s.name == CBLINK_DATASTORE_NAME_RUNNING ? CBL_YDS_RUNNING :
	    s.name == CBLINK_DATASTORE_NAME_CANDIDATE ? CBL_YDS_CANDIDATE :
	    CBL_YDS_OPERATIONAL;
	return (0);
}

/* The top-level nodes v of tree t (all where n is 0) into reply, what
 * the user may not read and what xpath does not select left out. */
static int
put_tree(cbl_req *req, cbl_msg *reply, cbl_dtree *t, const uint64_t *v,
    size_t n, const char *xpath, int wd)
{
	struct cbl_ybuf b = { NULL, 0, 0 };
	cbl_dtree *ft = NULL;
	cbl_dnode *c, *next;
	char why[160];
	int error;

	/* Those not asked for out. */
	for (c = cbl_dnode_first(cbl_dtree_root(t)); n > 0 && c != NULL;
	    c = next) {
		size_t i;

		next = cbl_dnode_next(c);
		for (i = 0; i < n && v[i] != cbl_dnode_schema(c)->sid; i++)
			;
		if (i == n)
			(void)cbl_dnode_remove(c);
	}
	if ((error = cbl_ynacm_read(req->conn->ctx, req->conn,
	    &(struct cbl_ywho){ req->user, req->recovery }, t)) != 0)
		return (error);
	if (xpath != NULL && (ft = cbl_dtree_filter_xpath(t, xpath, why,
	    sizeof(why))) == NULL)
		return (cbl_ysay(req, EINVAL, 0, "invalid-value", why));
	/* A filter's copy has no annotations: made on what goes. */
	if (wd == CBLINK_GET_WITH_DEFAULTS_REPORT_ALL_TAGGED &&
	    (error = cbl_yget_annotate(req, ft != NULL ? ft : t, false,
	    true)) != 0) {
		cbl_dtree_free(ft);
		return (error);
	}
	for (c = cbl_dnode_first(cbl_dtree_root(ft != NULL ? ft : t));
	    error == 0 && c != NULL; c = cbl_dnode_next(c)) {
		if ((error = cbl_dnode_encode(c, &b)) == 0)
			error = cbl_msg_put_sid_raw(reply,
			    cbl_dnode_schema(c)->sid, b.p, b.len);
		cbl_ybuf_free(&b);
		memset(&b, 0, sizeof(b));
	}
	cbl_dtree_free(ft);
	return (error);
}

int
cbl_yds_get(cbl_req *req, cbl_msg *reply, const uint64_t *v, size_t n,
    const char *xpath, enum cbl_yds_name ds, int wd)
{
	struct cbl_yds *d = req->conn->ctx->yds;
	cbl_dtree *t;
	int error;

	pthread_mutex_lock(&d->lock);
	if (ds == CBL_YDS_CANDIDATE && d->cand != NULL)
		t = tree_copy(d->cand);
	else
		t = NULL;
	pthread_mutex_unlock(&d->lock);
	if (t == NULL && ds == CBL_YDS_CANDIDATE && d->cand != NULL)
		return (ENOMEM);
	if (t == NULL && (error = cbl_yds_running(req, &t)) != 0)
		return (error);
	if ((error = cbl_ywd_apply(t, wd)) == 0)
		error = put_tree(req, reply, t, v, n, xpath, wd);
	cbl_dtree_free(t);
	return (error);
}

bool
cbl_yds_running_locked(cbl_req *req)
{
	struct cbl_yds *d = req->conn->ctx->yds;

	return (d != NULL && (d->flags & CBL_YDS_CONFIRMED) != 0);
}

/*
 * An EDIT of the candidate: each node it names checked as an EDIT of
 * running is (decoded, valid, NACM's write) against the candidate, then
 * put in its place there.  Nothing is changed but the candidate.
 */
/* The conditions of the top-level nodes msg edits, in cand. */
static int
edited_conds(cbl_req *req, const cbl_msg *msg, const cbl_dtree *cand)
{
	const cbl_attr *body = cbl_msg_body(msg);
	struct cbl_dederr err;
	struct cbl_yfound f;
	cbl_dtree *t;
	int error = 0;

	if ((t = tree_copy(cand)) == NULL)
		return (ENOMEM);
	if (cbl_dtree_defaults(cbl_dtree_root(t)) < 0) {
		cbl_dtree_free(t);
		return (errno != 0 ? errno : ENOMEM);
	}
	for (uint32_t i = 0; error == 0 && i < body->count; i++) {
		const cbl_attr *at = &body->child[i];

		if (at->key < 1 || cbl_fw_sid((uint64_t)at->key) ||
		    !cbl_yfind(req->conn->ctx, (uint64_t)at->key, &f))
			continue;
		for (const cbl_dnode *c = cbl_dnode_first(cbl_dtree_root(t));
		    error == 0 && c != NULL; c = cbl_dnode_next(c))
			if (cbl_dnode_schema(c) == f.n &&
			    (error = cbl_dnode_check_conds(t, c, &err)) != 0) {
				if (err.apptag != NULL)
					(void)cbl_req_set_yapptag(req,
					    err.apptag);
				error = cbl_ysay(req, error, f.n->sid,
				    err.tag != NULL ? err.tag :
				    "operation-failed", err.msg);
			}
	}
	cbl_dtree_free(t);
	return (error);
}

int
cbl_yds_edit(cbl_req *req, const cbl_msg *msg)
{
	struct cbl_yds *d = req->conn->ctx->yds;
	const cbl_attr *body = cbl_msg_body(msg), *at;
	struct cbl_yfound f;
	cbl_dnode *c, *next;
	cbl_dtree *cand;
	cbl_yarena *a;
	const uint8_t *raw;
	uint8_t *p;
	size_t len;
	void *before, *after;
	char why[160];
	int error = 0;

	if (body == NULL || body->count == 0)
		return (0);
	pthread_mutex_lock(&d->lock);
	if (d->cand == NULL && (error = cbl_yds_running(req, &d->cand)) != 0) {
		pthread_mutex_unlock(&d->lock);
		return (error);
	}
	/* On a copy: all or nothing. */
	if ((cand = tree_copy(d->cand)) == NULL) {
		pthread_mutex_unlock(&d->lock);
		return (ENOMEM);
	}
	for (uint32_t i = 0; error == 0 && i < body->count; i++) {
		uint64_t sid;

		at = &body->child[i];
		if (at->key < 1 || cbl_fw_sid((uint64_t)at->key))
			continue;
		sid = (uint64_t)at->key;
		if (!cbl_yfind(req->conn->ctx, sid, &f) ||
		    !cbl_yis_top_data(f.n)) {
			error = cbl_ysay(req, ENOENT, sid, "unknown-element",
			    "no such node");
			break;
		}
		if ((f.n->flags & CBL_YNF_CONFIG) == 0 || f.h == NULL ||
		    f.h->edit == NULL) {
			error = cbl_ysay(req, EOPNOTSUPP, sid,
			    "operation-not-supported",
			    "the node is not configuration that is edited");
			break;
		}
		if ((a = cbl_yarena_new()) == NULL) {
			error = ENOMEM;
			break;
		}
		raw = msg->buf + msg->hdr.hdrlen + at->off;
		p = NULL;
		if ((error = top_bytes(cand, f.n, &p, &len)) == 0 &&
		    (before = struct_of(f.n, p, len, a, why, sizeof(why),
		    &error)) != NULL) {
			bool del = at->len == 1 && raw[0] == 0xf6;

			after = struct_of(f.n, del ? NULL : raw, at->len, a, why,
			    sizeof(why), &error);
			if (after == NULL)
				error = cbl_ysay(req, error, sid, "bad-element",
				    why);
			else if ((del || (error = cbl_yvalid_member(req, f.n,
			    after)) == 0) && (error = cbl_ynacm_write(req,
			    f.n, before, after)) == 0) {
				for (c = cbl_dnode_first(cbl_dtree_root(cand));
				    c != NULL; c = next) {
					next = cbl_dnode_next(c);
					if (cbl_dnode_schema(c) == f.n)
						(void)cbl_dnode_remove(c);
				}
				if (!del && (error = cbl_dnode_decode(
				    cbl_dtree_root(cand), f.n, raw, at->len,
				    CBL_YD_STRICT, why, sizeof(why), NULL)) != 0)
					error = cbl_ysay(req, error, sid,
					    "bad-element", why);
				if (error == 0)
					prune_state(cbl_dtree_root(cand));
			}
		}
		free(p);
		cbl_yarena_free(a);
	}
	/* when and must of the nodes edited, and what a when makes
	 * mandatory, on a copy with its defaults (RFC 7950 6.4.1). */
	if (error == 0)
		error = edited_conds(req, msg, cand);
	if (error == 0) {
		cbl_dtree_free(d->cand);
		d->cand = cand;
	} else
		cbl_dtree_free(cand);
	pthread_mutex_unlock(&d->lock);
	return (error);
}

/* A change a commit makes. */
struct change {
	struct cbl_yfound	 f;
	void			*before, *after;
	uint8_t			*was;	/* running's bytes; NULL: none */
	size_t			 len;
};

/*
 * The candidate put in use: every top-level node it has otherwise than
 * running, checked (valid, NACM's write) and then changed through its
 * handler in SID order, those done undone if one fails.  Each changed
 * node's running bytes into *chp (*nchp of them), for a confirmed
 * commit to keep.  d->lock held.
 */
static int
apply(cbl_req *req, struct cbl_yds *d, struct change **chp, size_t *nchp,
    cbl_yarena *a)
{
	struct change *ch = NULL;
	cbl_dtree *run = NULL;
	uint64_t *v = NULL;
	uint8_t *cp;
	size_t n = 0, nch = 0, done, clen;
	char why[160];
	int error;

	*chp = NULL;
	*nchp = 0;
	if (d->cand == NULL)
		return (0);
	if ((error = cbl_yds_running(req, &run)) != 0 ||
	    (error = config_sids(req->conn->ctx, true, &v, &n)) != 0)
		goto out;
	if (n > 0 && (ch = calloc(n, sizeof(*ch))) == NULL) {
		error = ENOMEM;
		goto out;
	}
	for (size_t i = 0; error == 0 && i < n; i++) {
		struct change *c = &ch[nch];

		if (!cbl_yfind(req->conn->ctx, v[i], &c->f))
			continue;
		cp = NULL;
		if ((error = top_bytes(run, c->f.n, &c->was, &c->len)) != 0 ||
		    (error = top_bytes(d->cand, c->f.n, &cp, &clen)) != 0) {
			free(cp);
			break;
		}
		if ((c->was == NULL && cp == NULL) || (c->was != NULL &&
		    cp != NULL && c->len == clen && memcmp(c->was, cp,
		    clen) == 0)) {
			free(c->was);
			c->was = NULL;
			free(cp);
			continue;
		}
		if ((c->before = struct_of(c->f.n, c->was, c->len, a, why,
		    sizeof(why), &error)) == NULL ||
		    (c->after = struct_of(c->f.n, cp, clen, a, why,
		    sizeof(why), &error)) == NULL)
			error = cbl_ysay(req, error, v[i], "bad-element", why);
		else if ((cp == NULL || (error = cbl_yvalid_member(req, c->f.n,
		    c->after)) == 0))
			error = cbl_ynacm_write(req, c->f.n, c->before,
			    c->after);
		free(cp);
		nch++;
	}
	/* done: the changes made; the one that failed is not. */
	for (done = 0; error == 0 && done < nch; ) {
		req->yarg = ch[done].f.arg;
		if ((error = ch[done].f.h->edit(req, ch[done].before,
		    ch[done].after)) != 0)
			error = cbl_yfailed(req, error, ch[done].f.n->sid,
			    "the commit failed");
		else
			done++;
	}
	/* Rollback on error (RFC 6241 section 7.2): the others undone. */
	if (error != 0 && done > 0) {
		/* Why it failed is the answer, whatever the undo says. */
		char *msg = req->err_msg, *tag = req->err_yapptag;
		const char *ytag = req->err_ytag;
		uint64_t ysid = req->err_ysid;

		req->err_msg = req->err_yapptag = NULL;
		req->yds_undo = true;
		while (done-- > 0) {
			req->yarg = ch[done].f.arg;
			(void)ch[done].f.h->edit(req, ch[done].after,
			    ch[done].before);
		}
		req->yds_undo = false;
		free(req->err_msg);
		free(req->err_yapptag);
		req->err_msg = msg;
		req->err_yapptag = tag;
		req->err_ytag = ytag;
		req->err_ysid = ysid;
	}
	/* The access rules changed, or were put back: read again; the
	 * on-change subscriptions told. */
	for (size_t i = 0; i < nch; i++) {
		if (strcmp(ch[i].f.n->module->name, "ietf-netconf-acm") == 0)
			cbl_ynacm_changed(req->conn->ctx);
		cbl_ysub_changed(req->conn->ctx, ch[i].f.n);
	}
out:
	free(v);
	cbl_dtree_free(run);
	if (error != 0) {
		for (size_t i = 0; i < nch; i++)
			free(ch[i].was);
		free(ch);
		return (error);
	}
	*chp = ch;
	*nchp = nch;
	return (0);
}

/* What a confirmed commit changed, its first value kept. */
static int
keep(struct cbl_yds *d, struct change *ch, size_t nch)
{
	struct saved *ns;
	size_t j;

	for (size_t i = 0; i < nch; i++) {
		for (j = 0; j < d->nsaved && d->saved[j].sid !=
		    ch[i].f.n->sid; j++)
			;
		if (j < d->nsaved)
			continue;	/* changed again: its first value */
		if ((ns = reallocarray(d->saved, d->nsaved + 1,
		    sizeof(*ns))) == NULL)
			return (ENOMEM);
		d->saved = ns;
		d->saved[d->nsaved].sid = ch[i].f.n->sid;
		d->saved[d->nsaved].p = ch[i].was;
		d->saved[d->nsaved].len = ch[i].len;
		ch[i].was = NULL;
		d->nsaved++;
	}
	return (0);
}

/* A leaf of an rpc's input, by name, as its canonical text (malloc'd);
 * NULL: not there.  The tree: the rpc, its input under it. */
static char *
input_leaf(const cbl_dtree *t, const char *name)
{
	const cbl_dnode *rpc, *in, *c;
	char *s = NULL;

	if ((rpc = cbl_dnode_first(cbl_dtree_root(t))) == NULL ||
	    (in = cbl_dnode_first(rpc)) == NULL)
		return (NULL);
	for (c = cbl_dnode_first(in); c != NULL; c = cbl_dnode_next(c))
		if (strcmp(cbl_dnode_schema(c)->name, name) == 0) {
			if (cbl_dnode_value(c) == NULL ||
			    cbl_d_vstring(cbl_dtree_schema(t),
			    cbl_dnode_schema(c)->type, cbl_dnode_value(c),
			    &s) != 0)
				return (strdup(""));
			return (s);
		}
	return (NULL);
}

/* The datastore rpcs: commit, cancel-commit, discard-changes. */
int
cbl_yds_rpc(cbl_req *req, const cbl_msg *msg, const struct cbl_ynode *n,
    bool *handled)
{
	struct cbl_yds *d = req->conn->ctx->yds;
	const struct cbl_ynode *in = NULL;
	struct change *ch = NULL;
	struct timespec now;
	cbl_dtree *t = NULL;
	cbl_dnode *rn;
	cbl_yarena *a;
	cbl_msg *reply;
	char *confirmed, *timeout, *persist, *pid, why[160];
	size_t nch = 0;
	void *pin;
	int error;
	bool was;

	*handled = false;
	if (d == NULL || strcmp(n->module->name, "ietf-netconf") != 0 ||
	    (strcmp(n->name, "commit") != 0 && strcmp(n->name,
	    "cancel-commit") != 0 && strcmp(n->name, "discard-changes") != 0))
		return (0);
	*handled = true;
	if ((error = cbl_ynacm_exec(req, n)) != 0)
		return (error);
	for (uint32_t i = 0; i < n->nchild; i++)
		if (n->child[i]->kind == CBL_YN_INPUT)
			in = n->child[i];
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	/* The input, read by name: a tree of the rpc and it. */
	why[0] = '\0';
	if (in != NULL && ((pin = cbl_yarena_alloc(a, in->size)) == NULL ||
	    (error = cbl_msg_ydecode(msg, in, pin, a, CBL_YD_STRICT, why,
	    sizeof(why))) != 0 || (t = cbl_dtree_new(n->module->schema)) ==
	    NULL || (error = cbl_dnode_add(cbl_dtree_root(t), n, NULL,
	    &rn)) != 0 || (error = cbl_dnode_from_struct(rn, in, pin,
	    NULL)) != 0)) {
		cbl_yarena_free(a);
		cbl_dtree_free(t);
		return (cbl_ysay(req, error != 0 ? error : ENOMEM, n->sid,
		    "bad-element", why));
	}
	confirmed = t != NULL ? input_leaf(t, "confirmed") : NULL;
	timeout = t != NULL ? input_leaf(t, "confirm-timeout") : NULL;
	persist = t != NULL ? input_leaf(t, "persist") : NULL;
	pid = t != NULL ? input_leaf(t, "persist-id") : NULL;
	cbl_dtree_free(t);
	pthread_mutex_lock(&d->lock);
	was = d->pending;
	if (strcmp(n->name, "discard-changes") == 0) {
		cbl_dtree_free(d->cand);
		d->cand = NULL;
	} else if (strcmp(n->name, "cancel-commit") == 0) {
		if (!d->pending)
			error = cbl_ysay(req, ENOENT, n->sid, "operation-failed",
			    "no confirmed commit waits");
		else if (d->persist != NULL ? pid == NULL ||
		    strcmp(pid, d->persist) != 0 : d->by != req->conn)
			error = cbl_ysay(req, EACCES, n->sid, "invalid-value",
			    d->persist != NULL ? "not its persist-id" :
			    "another session's confirmed commit");
		else
			rollback(d, req->conn);
	} else {
		/* A waiting one: confirmed (or extended) by its own. */
		if (d->pending && (d->persist != NULL ? pid == NULL ||
		    strcmp(pid, d->persist) != 0 : d->by != req->conn))
			error = cbl_ysay(req, EBUSY, n->sid, "in-use",
			    d->persist != NULL ? "a confirmed commit waits: "
			    "give its persist-id" : "a confirmed commit of "
			    "another session waits");
		else if (!d->pending && pid != NULL)
			error = cbl_ysay(req, ENOENT, n->sid, "invalid-value",
			    "no confirmed commit of that persist-id waits");
		if (error == 0 && (error = apply(req, d, &ch, &nch, a)) == 0) {
			cbl_dtree_free(d->cand);
			d->cand = NULL;
		}
		if (error == 0 && confirmed != NULL) {
			if ((error = keep(d, ch, nch)) == 0) {
				long secs = timeout != NULL ? strtol(timeout,
				    NULL, 10) : CONFIRM_TIMEOUT;

				(void)clock_gettime(CLOCK_REALTIME, &now);
				d->deadline = now;
				d->deadline.tv_sec += secs > 0 ? secs :
				    CONFIRM_TIMEOUT;
				d->pending = true;
				free(d->persist);
				d->persist = persist != NULL ? strdup(persist) :
				    NULL;
				d->by = req->conn;
				if (d->timer == 0 && pthread_create(&d->timer,
				    NULL, timer_run, d) != 0) {
					d->timer = 0;
					rollback(d, req->conn);
					error = cbl_ysay(req, EAGAIN, n->sid,
					    "resource-denied", "no timer for "
					    "the confirmed commit: undone");
				}
				pthread_cond_broadcast(&d->cv);
			}
		} else if (error == 0 && was) {
			/* Confirmed: what it changed stays. */
			for (size_t i = 0; i < d->nsaved; i++)
				free(d->saved[i].p);
			free(d->saved);
			d->saved = NULL;
			d->nsaved = 0;
			d->pending = false;
			free(d->persist);
			d->persist = NULL;
			d->by = NULL;
			pthread_cond_broadcast(&d->cv);
		}
	}
	pthread_mutex_unlock(&d->lock);
	for (size_t i = 0; i < nch; i++)
		free(ch[i].was);
	free(ch);
	free(confirmed);
	free(timeout);
	free(persist);
	free(pid);
	cbl_yarena_free(a);
	if (error != 0)
		return (error);
	if ((error = cbl_req_reply_new(req, 0, &reply)) != 0)
		return (error);
	if ((error = cbl_msg_put_ynull(reply, n->sid)) == 0 &&
	    (error = cbl_yds_put_warnings(req, reply)) == 0)
		return (cbl_req_send(req, reply));
	cbl_msg_free(reply);
	return (error);
}

/* The warnings and accepts of requests. */
int
cbl_msg_set_datastore(cbl_msg *msg, enum cbl_yds_name ds)
{
	struct cblink_datastore s = { .has_name = true };

	if (msg == NULL)
		return (EINVAL);
	s.name = ds == CBL_YDS_RUNNING ? CBLINK_DATASTORE_NAME_RUNNING :
	    ds == CBL_YDS_CANDIDATE ? CBLINK_DATASTORE_NAME_CANDIDATE :
	    CBLINK_DATASTORE_NAME_OPERATIONAL;
	return (cblink_datastore_put(msg, &s));
}

int
cbl_msg_set_accept(cbl_msg *msg, const char *const *tags, size_t n)
{
	struct cblink_accept s = { .warning = { n, tags } };

	if (msg == NULL || (n > 0 && tags == NULL))
		return (EINVAL);
	return (cblink_accept_put(msg, &s));
}

int
cbl_msg_ywarnings(const cbl_msg *msg, cbl_yarena *a,
    const struct cbl_ywarning **vp, size_t *np)
{
	struct cblink_warnings w;
	struct cbl_ywarning *v;
	int error;

	*vp = NULL;
	*np = 0;
	if ((error = cbl_msg_ydecode(msg, cbl_fw_node("warnings"), &w, a, 0,
	    NULL, 0)) != 0)
		return (error == ENOENT ? 0 : error);
	if (w.warning.n == 0)
		return (0);
	if ((v = cbl_yarena_alloc(a, w.warning.n * sizeof(*v))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < w.warning.n; i++) {
		v[i].sid = w.warning.v[i].error_path;
		v[i].tag = w.warning.v[i].error_app_tag;
		v[i].text = w.warning.v[i].error_message;
	}
	*vp = v;
	*np = w.warning.n;
	return (0);
}

bool
cbl_req_yaccepts(cbl_req *req, const char *tag)
{
	struct cblink_accept s;
	cbl_yarena *a;

	if (req == NULL || tag == NULL)
		return (false);
	/* An undo puts back what was: its commit's consent holds. */
	if (req->yds_undo)
		return (true);
	if (!req->accepts_read && req->msg != NULL) {
		req->accepts_read = true;
		if ((a = cbl_yarena_new()) != NULL) {
			if (cbl_msg_ydecode(req->msg, cbl_fw_node("accept"), &s,
			    a, 0, NULL, 0) == 0 && s.warning.n > 0 &&
			    (req->accepts = calloc(s.warning.n,
			    sizeof(*req->accepts))) != NULL)
				for (size_t i = 0; i < s.warning.n; i++)
					if ((req->accepts[req->naccepts] =
					    strdup(s.warning.v[i])) != NULL)
						req->naccepts++;
			cbl_yarena_free(a);
		}
	}
	for (size_t i = 0; i < req->naccepts; i++)
		if (strcmp(req->accepts[i], tag) == 0)
			return (true);
	return (false);
}

int
cbl_req_set_yapptag(cbl_req *req, const char *tag)
{
	char *t;

	if (req == NULL || tag == NULL || strlen(tag) > 64)
		return (EINVAL);
	if ((t = strdup(tag)) == NULL)
		return (ENOMEM);
	free(req->err_yapptag);
	req->err_yapptag = t;
	return (0);
}

int
cbl_req_ywarn(cbl_req *req, uint64_t sid, const char *tag, const char *text)
{
	struct cbl_ywarn_out *nw;

	if (req == NULL || tag == NULL || text == NULL)
		return (EINVAL);
	if ((nw = reallocarray(req->warns, req->nwarns + 1, sizeof(*nw))) ==
	    NULL)
		return (ENOMEM);
	req->warns = nw;
	nw[req->nwarns].sid = sid;
	if ((nw[req->nwarns].tag = strdup(tag)) == NULL ||
	    (nw[req->nwarns].text = strdup(text)) == NULL) {
		free(nw[req->nwarns].tag);
		return (ENOMEM);
	}
	req->nwarns++;
	return (0);
}

int
cbl_yds_put_warnings(cbl_req *req, cbl_msg *reply)
{
	struct cblink_warnings_warning *v;
	struct cblink_warnings w;
	int error;

	if (req->nwarns == 0)
		return (0);
	if ((v = calloc(req->nwarns, sizeof(*v))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < req->nwarns; i++) {
		v[i].has_error_path = true;
		v[i].error_path = req->warns[i].sid;
		v[i].error_app_tag = req->warns[i].tag;
		v[i].error_message = req->warns[i].text;
	}
	w.warning.n = req->nwarns;
	w.warning.v = v;
	error = cblink_warnings_put(reply, &w);
	free(v);
	return (error);
}

void
cbl_yds_req_free(cbl_req *req)
{

	for (size_t i = 0; i < req->naccepts; i++)
		free(req->accepts[i]);
	free(req->accepts);
	for (size_t i = 0; i < req->nwarns; i++) {
		free(req->warns[i].tag);
		free(req->warns[i].text);
	}
	free(req->warns);
}
