/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Family 1, "cblink.yang" (PLAN-SDN-YANG, "cblink 2: the protocol"): the
 * handlers of a program's YANG modules (cbl_yserver, cblink-gen -m
 * server) served by SID, in CORECONF's shape (draft-ietf-core-comi):
 *
 *	GET	{cblink:get: {target: [SID...]}}, or nothing: the whole
 *		datastore.  The reply {SID: value, ...}; a dump, one
 *		MULTI frame a node.  A node not there is left out.
 *	EDIT	{SID: value or null, ...}, as iPATCH: a value creates or
 *		replaces the node, null deletes it.  All or nothing: an
 *		edit that fails undoes those before it.
 *	RPC	{SID(rpc): input or null}; the reply {SID(rpc): output},
 *		null when the rpc has none.
 *
 * A request's targets are top-level nodes; a list entry's (a SID with
 * keys), actions and the .sid files (GET-SID) are for what comes next.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_impl.h"
#include "cbl_schema.h"
#include "cbl_ymod.h"

/* A node of a served module: its server, handlers and node. */
struct yfound {
	const struct cbl_yserver	*srv;
	void				*arg;
	const struct cbl_ynode		*n;
	const struct cbl_yhandler	*h;	/* NULL: none */
};

static int
hcmp(const void *key, const void *elem)
{
	uint64_t sid = *(const uint64_t *)key;
	const struct cbl_yhandler *h = elem;

	return ((sid > h->sid) - (sid < h->sid));
}

static const struct cbl_yhandler *
handler_of(const struct cbl_yserver *srv, uint64_t sid)
{

	if (srv->nhandler == 0)
		return (NULL);
	return (bsearch(&sid, srv->handler, srv->nhandler,
	    sizeof(*srv->handler), hcmp));
}

static bool
yfind(cbl_ctx *ctx, uint64_t sid, struct yfound *f)
{
	const struct cbl_ynode *n;
	bool found = false;

	pthread_rwlock_rdlock(&ctx->famlock);
	for (size_t i = 0; i < ctx->nysrv && !found; i++) {
		if ((n = cbl_yschema_node(ctx->ysrv[i].srv->schema, sid)) ==
		    NULL)
			continue;
		f->srv = ctx->ysrv[i].srv;
		f->arg = ctx->ysrv[i].arg;
		f->n = n;
		f->h = handler_of(f->srv, sid);
		found = true;
	}
	pthread_rwlock_unlock(&ctx->famlock);
	return (found);
}

/* Is n one of its module's top-level nodes? */
static bool
is_top(const struct cbl_ynode *n)
{
	const struct cbl_ymodule *m = n->module;
	uint32_t lo = 0, hi = m->ntop, mid;

	while (lo < hi) {
		mid = lo + (hi - lo) / 2;
		if (m->top[mid]->sid == n->sid)
			return (true);
		if (m->top[mid]->sid < n->sid)
			lo = mid + 1;
		else
			hi = mid;
	}
	return (false);
}

/* A top-level data node: what GET reads and EDIT changes. */
static bool
is_top_data(const struct cbl_ynode *n)
{

	switch (n->kind) {
	case CBL_YN_CONTAINER:
	case CBL_YN_LIST:
	case CBL_YN_LEAF:
	case CBL_YN_LEAFLIST:
	case CBL_YN_ANYDATA:
	case CBL_YN_ANYXML:
		return (n->module->size != 0 && is_top(n));
	default:
		return (false);
	}
}

/* Why a request failed: its message, the node by SID, the tag. */
static int
ysay(cbl_req *req, int error, uint64_t sid, const char *tag,
    const char *text)
{

	if (text != NULL)
		(void)cbl_req_set_err(req, text, NULL, 0, -1);
	req->err_ysid = sid;
	req->err_ytag = tag;
	return (error);
}

/* A handler's failure: the node, and its message if it gave none. */
static int
yfailed(cbl_req *req, int error, uint64_t sid, const char *what)
{

	return (ysay(req, error, sid, NULL, req->err_msg == NULL ? what :
	    NULL));
}

/*
 * An instance-identifier of a target: a SID alone.  One with keys is a
 * list entry's, for later.
 */
static int
iid_sid(cbl_req *req, const struct cbl_bytes *b, uint64_t *sidp)
{
	const uint8_t *p = b->p;
	uint64_t v;
	size_t n;

	if (b->len == 0)
		return (ysay(req, EINVAL, 0, "bad-element", "empty target"));
	if ((p[0] & 0xe0) == 0x80)
		return (ysay(req, EOPNOTSUPP, 0, "operation-not-supported",
		    "a list entry as a target: not yet"));
	if ((p[0] & 0xe0) != 0)
		return (ysay(req, EINVAL, 0, "bad-element",
		    "a target is a SID"));
	v = p[0] & 0x1f;
	if (v >= 24) {
		if (v > 27 || b->len != 1 + ((size_t)1 << (v - 24)))
			return (ysay(req, EINVAL, 0, "bad-element",
			    "a target is a SID"));
		n = b->len - 1;
		for (v = 0; n > 0; n--)
			v = v << 8 | *++p;
	} else if (b->len != 1)
		return (ysay(req, EINVAL, 0, "bad-element", "a target is a SID"));
	*sidp = v;
	return (0);
}

static int
sid_cmp(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return ((x > y) - (x < y));
}

/*
 * What a GET reads, ascending and each once: its targets, or every
 * top-level data node with a get handler.
 */
static int
get_targets(cbl_req *req, const cbl_msg *msg, uint64_t **vp, size_t *np)
{
	cbl_ctx *ctx = req->conn->ctx;
	struct cblink_get g;
	uint64_t *v = NULL;
	size_t n = 0, k;
	cbl_yarena *a;
	char why[128];
	int error;

	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	error = cbl_msg_ydecode(msg, cbl_fw_node("get"), &g, a, CBL_YD_STRICT,
	    why, sizeof(why));
	if (error == 0 && g.target.n > 0) {
		if ((v = calloc(g.target.n, sizeof(*v))) == NULL)
			error = ENOMEM;
		for (size_t i = 0; error == 0 && i < g.target.n; i++)
			error = iid_sid(req, &g.target.v[i], &v[n++]);
	} else if (error == 0 || error == ENOENT) {
		/* The whole datastore. */
		error = 0;
		pthread_rwlock_rdlock(&ctx->famlock);
		for (size_t i = 0; i < ctx->nysrv; i++)
			n += ctx->ysrv[i].srv->nhandler;
		if (n > 0 && (v = calloc(n, sizeof(*v))) == NULL)
			error = ENOMEM;
		for (size_t i = n = 0; error == 0 && i < ctx->nysrv; i++) {
			const struct cbl_yserver *s = ctx->ysrv[i].srv;

			for (uint32_t j = 0; j < s->nhandler; j++) {
				const struct cbl_ynode *nd = cbl_yschema_node(
				    s->schema, s->handler[j].sid);

				if (s->handler[j].get != NULL && nd != NULL &&
				    is_top_data(nd))
					v[n++] = s->handler[j].sid;
			}
		}
		pthread_rwlock_unlock(&ctx->famlock);
	} else
		error = ysay(req, error, 0, "malformed-message", why);
	cbl_yarena_free(a);
	if (error != 0) {
		free(v);
		return (error);
	}
	if (n > 1) {
		qsort(v, n, sizeof(*v), sid_cmp);
		for (size_t i = k = 1; i < n; i++)
			if (v[i] != v[k - 1])
				v[k++] = v[i];
		n = k;
	}
	*vp = v;
	*np = n;
	return (0);
}

/* A node's value into reply, through its get handler. */
static int
get_one(cbl_req *req, cbl_msg *reply, uint64_t sid, bool *put)
{
	struct yfound f;
	cbl_yarena *a;
	void *data;
	int error;

	*put = false;
	if (!yfind(req->conn->ctx, sid, &f) || !is_top_data(f.n))
		return (ysay(req, ENOENT, sid, "unknown-element",
		    "no such node"));
	if (f.h == NULL || f.h->get == NULL)
		return (ysay(req, EOPNOTSUPP, sid, "operation-not-supported",
		    "the node is not read"));
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if ((data = cbl_yarena_alloc(a, f.n->module->size)) == NULL)
		error = ENOMEM;
	else {
		req->yarg = f.arg;
		if ((error = f.h->get(req, data, a)) != 0)
			error = yfailed(req, error, sid, "reading it failed");
		else if (cbl_ymember_present(f.n, data)) {
			error = cbl_msg_put_ymember(reply, f.n, data);
			*put = error == 0;
		}
	}
	cbl_yarena_free(a);
	return (error);
}

static int
y_get(cbl_req *req, const cbl_msg *msg, void *arg __unused)
{
	cbl_msg *reply;
	uint64_t *v;
	size_t n;
	bool put;
	int error;

	if ((error = get_targets(req, msg, &v, &n)) != 0)
		return (error);
	if ((error = cbl_req_reply_new(req, 0, &reply)) != 0) {
		free(v);
		return (error);
	}
	for (size_t i = 0; error == 0 && i < n; i++)
		error = get_one(req, reply, v[i], &put);
	free(v);
	if (error != 0) {
		cbl_msg_free(reply);
		return (error);
	}
	return (cbl_req_send(req, reply));
}

struct ydump {
	uint64_t	*v;
	size_t		 n;
};

static void
ydump_free(void *p)
{
	struct ydump *d = p;

	free(d->v);
	free(d);
}

/* A dump: one frame a node, those not there left out. */
static int
y_get_dump(cbl_req *req, const cbl_msg *msg, struct cbl_dump_state *st,
    void *arg __unused)
{
	struct ydump *d = st->priv;
	cbl_msg *item;
	bool put;
	int error;

	if (d == NULL) {
		if ((d = calloc(1, sizeof(*d))) == NULL)
			return (ENOMEM);
		if ((error = get_targets(req, msg, &d->v, &d->n)) != 0) {
			free(d);
			return (error);
		}
		st->priv = d;
		st->priv_free = ydump_free;
	}
	for (; st->pos[0] < d->n; st->pos[0]++) {
		if ((error = cbl_req_dump_item(req, &item)) != 0)
			return (error);
		if ((error = get_one(req, item, d->v[st->pos[0]], &put)) != 0) {
			cbl_msg_free(item);
			return (error);
		}
		if (!put) {
			cbl_msg_free(item);
			continue;
		}
		st->pos[0]++;
		if ((error = cbl_req_send(req, item)) != 0)
			return (error);
		return (EAGAIN);
	}
	return (0);
}

struct yedit {
	struct yfound	 f;
	void		*before;
	void		*after;
};

/*
 * EDIT: each node's new value decoded and its present one read first, so
 * a bad request changes nothing; then the edits in SID order, those done
 * undone if one fails.
 */
static int
y_edit(cbl_req *req, const cbl_msg *msg, void *arg __unused)
{
	const cbl_attr *body = cbl_msg_body(msg), *at;
	struct yedit *e = NULL;
	const uint8_t *raw;
	size_t n = 0, done;
	cbl_yarena *a;
	char why[128];
	uint64_t sid;
	int error = 0;

	if (body == NULL || body->count == 0)
		return (0);
	if ((a = cbl_yarena_new()) == NULL ||
	    (e = calloc(body->count, sizeof(*e))) == NULL) {
		cbl_yarena_free(a);
		return (ENOMEM);
	}
	for (uint32_t i = 0; error == 0 && i < body->count; i++) {
		at = &body->child[i];
		if (at->key < 1 || cbl_fw_sid((uint64_t)at->key))
			continue;
		sid = (uint64_t)at->key;
		if (!yfind(req->conn->ctx, sid, &e[n].f) ||
		    !is_top_data(e[n].f.n)) {
			error = ysay(req, ENOENT, sid, "unknown-element",
			    "no such node");
			break;
		}
		if ((e[n].f.n->flags & CBL_YNF_CONFIG) == 0 ||
		    e[n].f.h == NULL || e[n].f.h->edit == NULL) {
			error = ysay(req, EOPNOTSUPP, sid,
			    "operation-not-supported",
			    "the node is not configuration that is edited");
			break;
		}
		if ((e[n].before = cbl_yarena_alloc(a,
		    e[n].f.n->module->size)) == NULL ||
		    (e[n].after = cbl_yarena_alloc(a,
		    e[n].f.n->module->size)) == NULL) {
			error = ENOMEM;
			break;
		}
		raw = msg->buf + msg->hdr.hdrlen + at->off;
		/* null: deleted, after it nothing. */
		if (!(at->len == 1 && raw[0] == 0xf6) &&
		    (error = cbl_ydecode_member(e[n].f.n, raw, at->len,
		    e[n].after, a, CBL_YD_STRICT, why, sizeof(why))) != 0) {
			error = ysay(req, error, sid, "bad-element", why);
			break;
		}
		req->yarg = e[n].f.arg;
		if (e[n].f.h->get != NULL && (error = e[n].f.h->get(req,
		    e[n].before, a)) != 0) {
			error = yfailed(req, error, sid, "reading it failed");
			break;
		}
		n++;
	}
	for (done = 0; error == 0 && done < n; done++) {
		req->yarg = e[done].f.arg;
		if ((error = e[done].f.h->edit(req, e[done].before,
		    e[done].after)) != 0)
			error = yfailed(req, error, e[done].f.n->sid,
			    "the edit failed");
	}
	/* Rollback on error (RFC 6241 section 7.2): the others undone. */
	if (error != 0)
		while (done-- > 0) {
			req->yarg = e[done].f.arg;
			(void)e[done].f.h->edit(req, e[done].after,
			    e[done].before);
		}
	free(e);
	cbl_yarena_free(a);
	return (error);
}

/* The input or the output of an rpc. */
static const struct cbl_ynode *
io_of(const struct cbl_ynode *rpc, int kind)
{

	for (uint32_t i = 0; i < rpc->nchild; i++)
		if (rpc->child[i]->kind == kind)
			return (rpc->child[i]);
	return (NULL);
}

static int
y_rpc(cbl_req *req, const cbl_msg *msg, void *arg __unused)
{
	const cbl_attr *body = cbl_msg_body(msg), *at = NULL;
	const struct cbl_ynode *in, *out;
	struct yfound f;
	cbl_msg *reply;
	void *pin, *pout;
	cbl_yarena *a;
	char why[128];
	uint64_t sid;
	int error;

	for (uint32_t i = 0; body != NULL && i < body->count; i++) {
		if (body->child[i].key < 1 ||
		    cbl_fw_sid((uint64_t)body->child[i].key))
			continue;
		if (at != NULL)
			return (ysay(req, EINVAL, 0, "bad-element",
			    "one rpc a request"));
		at = &body->child[i];
	}
	if (at == NULL)
		return (ysay(req, EINVAL, 0, "missing-element", "no rpc"));
	sid = (uint64_t)at->key;
	if (!yfind(req->conn->ctx, sid, &f) || f.n->kind != CBL_YN_RPC)
		return (ysay(req, ENOENT, sid, "unknown-element",
		    "no such rpc"));
	if (f.h == NULL || f.h->rpc == NULL)
		return (ysay(req, EOPNOTSUPP, sid, "operation-not-supported",
		    "the rpc is not served"));
	if ((in = io_of(f.n, CBL_YN_INPUT)) == NULL ||
	    (out = io_of(f.n, CBL_YN_OUTPUT)) == NULL)
		return (ysay(req, EOPNOTSUPP, sid, "operation-not-supported",
		    "the rpc's tables have no input or output"));
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if ((pin = cbl_yarena_alloc(a, in->size)) == NULL ||
	    (pout = cbl_yarena_alloc(a, out->size)) == NULL) {
		cbl_yarena_free(a);
		return (ENOMEM);
	}
	if ((error = cbl_msg_ydecode(msg, in, pin, a, CBL_YD_STRICT, why,
	    sizeof(why))) != 0) {
		cbl_yarena_free(a);
		return (ysay(req, error, sid, "bad-element", why));
	}
	req->yarg = f.arg;
	if ((error = f.h->rpc(req, pin, pout, a)) != 0) {
		cbl_yarena_free(a);
		return (yfailed(req, error, sid, "the rpc failed"));
	}
	if ((error = cbl_req_reply_new(req, 0, &reply)) == 0) {
		error = out->nchild == 0 ? cbl_msg_put_ynull(reply, sid) :
		    cbl_msg_put_ynode(reply, out, pout);
		if (error == 0)
			error = cbl_req_send(req, reply);
		else
			cbl_msg_free(reply);
	}
	cbl_yarena_free(a);
	return (error);
}

static const struct cbl_op yops[] = {
	{ CBL_YCMD_GET, CBL_OPF_DO | CBL_OPF_DUMP, "get", NULL, y_get,
	    y_get_dump, NULL },
	{ CBL_YCMD_EDIT, CBL_OPF_DO, "edit", NULL, y_edit, NULL, NULL },
	{ CBL_YCMD_RPC, CBL_OPF_DO, "rpc", NULL, y_rpc, NULL, NULL },
};

static const struct cbl_family_def ydef = {
	.abi = CBL_FAMILY_ABI,
	.name = "cblink.yang",
	.version = 1,
	.ops = yops,
	.nops = sizeof(yops) / sizeof(yops[0]),
};

int
cbl_yserver_add(cbl_ctx *ctx, const struct cbl_yserver *srv, void *arg)
{
	struct cbl_yserved *v;
	cbl_family *fam;
	int error;

	if (ctx == NULL || srv == NULL || srv->schema == NULL ||
	    (srv->nhandler > 0 && srv->handler == NULL))
		return (EINVAL);
	for (uint32_t i = 1; i < srv->nhandler; i++)
		if (srv->handler[i].sid <= srv->handler[i - 1].sid)
			return (EINVAL);
	pthread_rwlock_wrlock(&ctx->famlock);
	for (size_t i = 0; i < ctx->nysrv; i++)
		if (ctx->ysrv[i].srv == srv) {
			pthread_rwlock_unlock(&ctx->famlock);
			return (EEXIST);
		}
	v = reallocarray(ctx->ysrv, ctx->nysrv + 1, sizeof(*v));
	if (v == NULL) {
		pthread_rwlock_unlock(&ctx->famlock);
		return (ENOMEM);
	}
	ctx->ysrv = v;
	v[ctx->nysrv].srv = srv;
	v[ctx->nysrv].arg = arg;
	ctx->nysrv++;
	pthread_rwlock_unlock(&ctx->famlock);
	/* The first: family 1 comes to be; EEXIST, it is already. */
	error = cbl_ctx_add_fixed(ctx, &ydef, CBL_YANG_FAMILY, NULL, &fam);
	if (error == 0)
		ctx->yfam = fam;
	return (error == EEXIST ? 0 : error);
}

/* A GET's targets: the cblink:get structure, each a SID. */
int
cbl_msg_put_yget(cbl_msg *msg, const uint64_t *sids, size_t n)
{
	struct cblink_get g = { 0 };
	struct cbl_bytes *t;
	uint8_t *b;
	int error;

	if (msg == NULL || (sids == NULL && n > 0))
		return (EINVAL);
	if (n == 0)
		return (0);
	if ((t = calloc(n, sizeof(*t))) == NULL ||
	    (b = calloc(n, 9)) == NULL) {
		free(t);
		return (cbl_msg_fail(msg, ENOMEM, "out of memory"));
	}
	for (size_t i = 0; i < n; i++) {
		uint8_t *p = b + 9 * i;
		uint64_t v = sids[i];
		size_t k = v < 24 ? 0 : v <= UINT8_MAX ? 1 : v <= UINT16_MAX ?
		    2 : v <= UINT32_MAX ? 4 : 8;

		p[0] = (uint8_t)(k == 0 ? v : k == 1 ? 0x18 : k == 2 ? 0x19 :
		    k == 4 ? 0x1a : 0x1b);
		for (size_t j = 0; j < k; j++)
			p[1 + j] = (uint8_t)(v >> (8 * (k - 1 - j)));
		t[i].p = p;
		t[i].len = 1 + k;
	}
	g.target.n = n;
	g.target.v = t;
	error = cbl_msg_put_ynode(msg, cbl_fw_node("get"), &g);
	free(b);
	free(t);
	return (error);
}

void *
cbl_req_yarg(const cbl_req *req)
{

	return (req != NULL ? req->yarg : NULL);
}

int
cbl_req_set_yerr(cbl_req *req, const char *text, uint64_t sid)
{

	if (req == NULL)
		return (EINVAL);
	(void)ysay(req, 0, sid, NULL, text);
	return (0);
}

/* The context is going away. */
void
cbl_yfamily_free(cbl_ctx *ctx)
{

	free(ctx->ysrv);
	ctx->ysrv = NULL;
	ctx->nysrv = 0;
	ctx->yfam = NULL;
}
