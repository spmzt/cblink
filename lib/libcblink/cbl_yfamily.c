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
 *		replaces the node, null deletes it.  All or nothing: each
 *		value decoded and validated (cbl_yvalidate(), config
 *		only) before any change, and an edit that fails undoes
 *		those before it.
 *	RPC	{SID(rpc): input or null}, validated; the reply
 *		{SID(rpc): output}, null when the rpc has none.
 *	NOTIFY	to group "notify": {cblink:notification: {event-time,
 *		event: {delta: content}}}, the delta from event's SID
 *		(RFC 9254: anydata's keys are as a container's).
 *	GET-SID	a dump: {1301: the ietf-sid-file structure}, a frame for
 *		each module's .sid file, what a generic client decodes
 *		the others with.
 *
 * A request's targets are top-level nodes; a list entry's (a SID with
 * keys), actions and the .sid files (GET-SID) are for what comes next.
 */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cbl_data.h"
#include "cbl_impl.h"
#include "cbl_schema.h"
#include "cbl_yimpl.h"
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
 * The static validator's verdict on what a request brings: the node at
 * fault, the tag, the app-tag and the message, as the error says them.
 */
static int
yverdict(cbl_req *req, int error, const struct cbl_yverr *ve)
{

	if (error == 0)
		return (0);
	(void)cbl_req_set_err(req, ve->msg, NULL, 0, -1);
	req->err_ysid = ve->node != NULL ? ve->node->sid : 0;
	req->err_ytag = ve->tag;
	return (error);
}

static int
yvalid(cbl_req *req, const struct cbl_ynode *n, const void *p, int flags)
{
	struct cbl_yverr ve;

	return (yverdict(req, cbl_yvalidate(n, p, flags, &ve), &ve));
}

static int
yvalid_member(cbl_req *req, const struct cbl_ynode *n, const void *parent)
{
	struct cbl_yverr ve;

	return (yverdict(req, cbl_yvalidate_member(n, parent, CBL_YV_EDIT,
	    &ve), &ve));
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
get_targets(cbl_req *req, const cbl_msg *msg, uint64_t **vp, size_t *np,
    char **xpathp)
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
	/* Not there (the whole datastore): nothing of it read. */
	memset(&g, 0, sizeof(g));
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
	/* An xpath filter: copied, the arena goes. */
	*xpathp = NULL;
	if (error == 0 && g.xpath_filter != NULL &&
	    (*xpathp = strdup(g.xpath_filter)) == NULL)
		error = ENOMEM;
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

/*
 * The nodes v read through their get handlers, made one instance tree
 * (cbl_data.h) as their YANG-CBOR says, what xpath selects of it (with
 * the nodes above and a list entry's keys, RFC 6241 section 8.9) into
 * reply.  The nodes' servers are one, their schema the tree's.
 */
static int
get_filtered(cbl_req *req, cbl_msg *reply, const uint64_t *v, size_t n,
    const char *xpath)
{
	const struct cbl_yschema *schema = NULL;
	struct cbl_ybuf b = { NULL, 0, 0 };
	cbl_dtree *t = NULL, *ft;
	struct yfound f;
	cbl_yarena *a;
	cbl_dnode *c;
	void *data;
	char why[160];
	int error = 0;

	for (size_t i = 0; error == 0 && i < n; i++) {
		if (!yfind(req->conn->ctx, v[i], &f) || !is_top_data(f.n))
			return (ysay(req, ENOENT, v[i], "unknown-element",
			    "no such node"));
		if (f.h == NULL || f.h->get == NULL)
			continue;
		if (schema == NULL) {
			schema = f.srv->schema;
			if ((t = cbl_dtree_new(schema)) == NULL)
				return (ENOMEM);
		} else if (f.srv->schema != schema) {
			cbl_dtree_free(t);
			return (ysay(req, EOPNOTSUPP, v[i],
			    "operation-not-supported", "a filter's nodes are "
			    "of one server's modules"));
		}
		if ((a = cbl_yarena_new()) == NULL) {
			error = ENOMEM;
			break;
		}
		if ((data = cbl_yarena_alloc(a, f.n->module->size)) == NULL)
			error = ENOMEM;
		else {
			req->yarg = f.arg;
			if ((error = f.h->get(req, data, a)) != 0)
				error = yfailed(req, error, v[i],
				    "reading it failed");
			else if (cbl_ymember_present(f.n, data) &&
			    (error = cbl_yencode_member(f.n, data, &b)) == 0)
				error = cbl_dnode_decode(cbl_dtree_root(t), f.n,
				    b.p, b.len, 0, why, sizeof(why), NULL);
			cbl_ybuf_free(&b);
			memset(&b, 0, sizeof(b));
		}
		cbl_yarena_free(a);
	}
	if (error != 0 || t == NULL) {
		cbl_dtree_free(t);
		return (error);
	}
	if ((ft = cbl_dtree_filter_xpath(t, xpath, why, sizeof(why))) ==
	    NULL) {
		error = errno;
		cbl_dtree_free(t);
		return (ysay(req, error == ENOMEM ? ENOMEM : EINVAL, 0,
		    "invalid-value", why));
	}
	for (c = cbl_dnode_first(cbl_dtree_root(ft)); error == 0 && c != NULL;
	    c = cbl_dnode_next(c)) {
		if ((error = cbl_dnode_encode(c, &b)) == 0)
			error = cbl_msg_put_sid_raw(reply,
			    cbl_dnode_schema(c)->sid, b.p, b.len);
		cbl_ybuf_free(&b);
		memset(&b, 0, sizeof(b));
	}
	cbl_dtree_free(ft);
	cbl_dtree_free(t);
	return (error);
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
y_get_now(cbl_req *req, const cbl_msg *msg, void *arg __unused)
{
	cbl_msg *reply;
	uint64_t *v;
	char *xpath;
	size_t n;
	bool put;
	int error;

	if ((error = get_targets(req, msg, &v, &n, &xpath)) != 0)
		return (error);
	if ((error = cbl_req_reply_new(req, 0, &reply)) != 0) {
		free(v);
		free(xpath);
		return (error);
	}
	if (xpath != NULL)
		error = get_filtered(req, reply, v, n, xpath);
	for (size_t i = 0; xpath == NULL && error == 0 && i < n; i++)
		error = get_one(req, reply, v[i], &put);
	free(v);
	free(xpath);
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
	char *xpath;
	bool put;
	int error;

	if (d == NULL) {
		if ((d = calloc(1, sizeof(*d))) == NULL)
			return (ENOMEM);
		if ((error = get_targets(req, msg, &d->v, &d->n, &xpath)) !=
		    0) {
			free(d);
			return (error);
		}
		/* A dump is a node a frame: a filter is a GET's. */
		if (xpath != NULL) {
			free(xpath);
			free(d->v);
			free(d);
			return (ysay(req, EOPNOTSUPP, 0, "operation-not-supported",
			    "an xpath filter is for a GET, not a dump"));
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
y_edit_now(cbl_req *req, const cbl_msg *msg, void *arg __unused)
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
		if (!(at->len == 1 && raw[0] == 0xf6)) {
			if ((error = cbl_ydecode_member(e[n].f.n, raw, at->len,
			    e[n].after, a, CBL_YD_STRICT, why,
			    sizeof(why))) != 0) {
				error = ysay(req, error, sid, "bad-element",
				    why);
				break;
			}
			/* Configuration, valid as RFC 7950 has it. */
			if ((error = yvalid_member(req, e[n].f.n,
			    e[n].after)) != 0)
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

/*
 * An action's target, cblink:action's: an instance of the action's
 * parent (cbl_yiid_read() over the server's schema), a list entry with
 * its keys.  0, or an error said for the request.
 */
static int
action_target(cbl_req *req, const cbl_msg *msg, const struct cbl_yserver *srv,
    const struct cbl_ynode *act, struct cblink_action *ac, cbl_yarena *a)
{
	const struct cbl_ynode *n;
	const void **vals;
	size_t nvals;
	char why[128];
	int error;

	memset(ac, 0, sizeof(*ac));
	if ((error = cbl_msg_ydecode(msg, cbl_fw_node("action"), ac, a,
	    CBL_YD_STRICT, why, sizeof(why))) != 0)
		return (ysay(req, error == ENOENT ? EINVAL : error, act->sid,
		    "missing-element", error == ENOENT ? "an action needs "
		    "its target (cblink:action)" : why));
	if (cbl_yiid_read(srv->schema, &ac->target, &n, &vals, &nvals,
	    a) != 0 || n != act->parent)
		return (ysay(req, EINVAL, act->sid, "bad-element",
		    "the target is no instance of the action's node"));
	return (0);
}

static int
y_rpc_now(cbl_req *req, const cbl_msg *msg, void *arg __unused)
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
	if (!yfind(req->conn->ctx, sid, &f) || (f.n->kind != CBL_YN_RPC &&
	    f.n->kind != CBL_YN_ACTION))
		return (ysay(req, ENOENT, sid, "unknown-element",
		    "no such rpc or action"));
	if (f.h == NULL || (f.n->kind == CBL_YN_RPC ? f.h->rpc == NULL :
	    f.h->action == NULL))
		return (ysay(req, EOPNOTSUPP, sid, "operation-not-supported",
		    f.n->kind == CBL_YN_RPC ? "the rpc is not served" :
		    "the action is not served"));
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
	/* An rpc's input, valid as RFC 7950 has it. */
	if ((error = yvalid(req, in, pin, 0)) != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	req->yarg = f.arg;
	if (f.n->kind == CBL_YN_ACTION) {
		struct cblink_action ac;

		/* The node it acts on: an instance of its parent. */
		if ((error = action_target(req, msg, f.srv, f.n, &ac, a)) == 0)
			error = f.h->action(req, &ac.target, pin, pout, a);
	} else
		error = f.h->rpc(req, pin, pout, a);
	if (error != 0) {
		cbl_yarena_free(a);
		return (yfailed(req, error, sid, f.n->kind == CBL_YN_RPC ?
		    "the rpc failed" : "the action failed"));
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

/* GET-SID: the servers' .sid files, one a frame. */
static int
y_getsid_dump(cbl_req *req, const cbl_msg *msg __unused,
    struct cbl_dump_state *st, void *arg __unused)
{
	cbl_ctx *ctx = req->conn->ctx;
	const struct cbl_ysidfile *f = NULL;
	cbl_msg *item;
	int error;

	/* pos[0]: the server; pos[1]: its file. */
	pthread_rwlock_rdlock(&ctx->famlock);
	while (st->pos[0] < ctx->nysrv) {
		const struct cbl_yserver *s = ctx->ysrv[st->pos[0]].srv;

		if (st->pos[1] < s->nsidfile) {
			f = &s->sidfile[st->pos[1]++];
			break;
		}
		st->pos[0]++;
		st->pos[1] = 0;
	}
	pthread_rwlock_unlock(&ctx->famlock);
	if (f == NULL)
		return (0);
	if ((error = cbl_req_dump_item(req, &item)) != 0)
		return (error);
	if ((error = cbl_msg_put_sid_raw(item, CBL_YSID_FILE, f->cbor,
	    f->len)) != 0) {
		cbl_msg_free(item);
		return (error);
	}
	if ((error = cbl_req_send(req, item)) != 0)
		return (error);
	return (EAGAIN);
}

/*
 * A request on a thread of its own (cbl_yserver_threads()): deferred,
 * its handlers run there, its answer sent from there; the loop goes on
 * with the others.  Without threads, or where none can be made, here.
 */
struct ythread {
	cbl_req	*req;
	int	(*fn)(cbl_req *, const cbl_msg *, void *);
};

static void *
ythread(void *p)
{
	struct ythread *t = p;
	int error;

	error = t->fn(t->req, cbl_req_msg(t->req), NULL);
	(void)cbl_req_complete(t->req, error);
	free(t);
	return (NULL);
}

static int
ydefer(cbl_req *req, const cbl_msg *msg,
    int (*fn)(cbl_req *, const cbl_msg *, void *))
{
	struct ythread *t;
	pthread_t tid;
	int error;

	if (!atomic_load(&req->conn->ctx->ythreads) ||
	    (t = malloc(sizeof(*t))) == NULL)
		return (fn(req, msg, NULL));
	t->req = req;
	t->fn = fn;
	if (cbl_req_defer(req) != 0) {
		free(t);
		return (fn(req, msg, NULL));
	}
	if (pthread_create(&tid, NULL, ythread, t) != 0) {
		free(t);
		error = fn(req, msg, NULL);
		(void)cbl_req_complete(req, error);
		return (0);
	}
	(void)pthread_detach(tid);
	return (0);
}

static int
y_get(cbl_req *req, const cbl_msg *msg, void *arg __unused)
{

	return (ydefer(req, msg, y_get_now));
}

static int
y_edit(cbl_req *req, const cbl_msg *msg, void *arg __unused)
{

	return (ydefer(req, msg, y_edit_now));
}

static int
y_rpc(cbl_req *req, const cbl_msg *msg, void *arg __unused)
{

	return (ydefer(req, msg, y_rpc_now));
}

static const struct cbl_op yops[] = {
	{ .cmd = CBL_YCMD_GET, .flags = CBL_OPF_DO | CBL_OPF_DUMP,
	    .name = "get", .doit = y_get, .dumpit = y_get_dump },
	{ .cmd = CBL_YCMD_EDIT, .flags = CBL_OPF_DO, .name = "edit",
	    .doit = y_edit },
	{ .cmd = CBL_YCMD_RPC, .flags = CBL_OPF_DO, .name = "rpc",
	    .doit = y_rpc },
	{ .cmd = CBL_YCMD_GET_SID, .flags = CBL_OPF_DUMP, .name = "get-sid",
	    .dumpit = y_getsid_dump },
};

static const struct cbl_mcgrp ygroups[] = {
	{ "notify", 0 },
};

static const struct cbl_family_def ydef = {
	.abi = CBL_FAMILY_ABI,
	.name = "cblink.yang",
	.version = 1,
	.ops = yops,
	.nops = sizeof(yops) / sizeof(yops[0]),
	.mcgrps = ygroups,
	.nmcgrps = sizeof(ygroups) / sizeof(ygroups[0]),
};

/* A CBOR integer's head into p, major type 0 or 1: its length. */
static size_t
put_int(uint8_t *p, int64_t v)
{
	uint64_t u = v < 0 ? (uint64_t)(-(v + 1)) : (uint64_t)v;
	uint8_t major = v < 0 ? 0x20 : 0;
	size_t k = u < 24 ? 0 : u <= UINT8_MAX ? 1 : u <= UINT16_MAX ? 2 :
	    u <= UINT32_MAX ? 4 : 8;

	p[0] = (uint8_t)(major | (k == 0 ? u : k == 1 ? 24 : k == 2 ? 25 :
	    k == 4 ? 26 : 27));
	for (size_t i = 0; i < k; i++)
		p[1 + i] = (uint8_t)(u >> (8 * (k - 1 - i)));
	return (1 + k);
}

/* A CBOR head at p: its major type and value; 0, or EINVAL. */
static int
get_head(const uint8_t **pp, const uint8_t *end, int *major, uint64_t *v)
{
	const uint8_t *p = *pp;
	size_t k;

	if (p >= end)
		return (EINVAL);
	*major = p[0] >> 5;
	*v = p[0] & 0x1f;
	p++;
	if (*v >= 24) {
		if (*v > 27)
			return (EINVAL);
		k = (size_t)1 << (*v - 24);
		if ((size_t)(end - p) < k)
			return (EINVAL);
		for (*v = 0; k > 0; k--)
			*v = *v << 8 | *p++;
	}
	*pp = p;
	return (0);
}

static const struct cbl_ynode *
event_node(void)
{
	const struct cbl_ynode *e = cbl_fw_node("notification");

	for (uint32_t i = 0; e != NULL && i < e->nchild; i++)
		if (strcmp(e->child[i]->name, "event") == 0)
			return (e->child[i]);
	return (NULL);
}

int
cbl_ynotify(cbl_ctx *ctx, const struct cbl_ynode *n, const void *p)
{

	if (ctx == NULL)
		return (EINVAL);
	if (ctx->yfam == NULL)
		return (ENOENT);	/* no module served */
	return (cbl_ynotify_fam(ctx->yfam, 0, CBL_YCMD_NOTIFY, n, p));
}

/* A YANG notification to a group of a family: family 1's, or ctrl's. */
int
cbl_ynotify_fam(cbl_family *fam, uint32_t group_idx, uint16_t cmd,
    const struct cbl_ynode *n, const void *p)
{
	struct cblink_notification e = { 0 };
	const struct cbl_ynode *ev = event_node();
	struct cbl_ybuf c = { 0 };
	uint8_t head[1 + 9], *b = NULL;
	char t[sizeof("YYYY-MM-DDThh:mm:ss.uuuuuuZ")];
	struct timespec ts;
	struct tm tm;
	cbl_msg *msg;
	size_t hl;
	int error;

	if (fam == NULL || n == NULL || p == NULL ||
	    n->kind != CBL_YN_NOTIF || ev == NULL)
		return (EINVAL);
	if ((error = cbl_yencode(n, p, &c)) != 0)
		return (error);
	/* event: {delta: content}. */
	head[0] = 0xa1;
	hl = 1 + put_int(head + 1, (int64_t)(n->sid - ev->sid));
	if ((b = malloc(hl + c.len)) == NULL) {
		error = ENOMEM;
		goto out;
	}
	memcpy(b, head, hl);
	memcpy(b + hl, c.p, c.len);
	e.event.p = b;
	e.event.len = hl + c.len;
	(void)clock_gettime(CLOCK_REALTIME, &ts);
	(void)gmtime_r(&ts.tv_sec, &tm);
	hl = strftime(t, sizeof(t), "%Y-%m-%dT%H:%M:%S", &tm);
	(void)snprintf(t + hl, sizeof(t) - hl, ".%06ldZ",
	    ts.tv_nsec / 1000);
	e.event_time = t;
	if ((error = cbl_notify_msg_new(fam, cmd, &msg)) != 0)
		goto out;
	if ((error = cbl_msg_put_ynode(msg, cbl_fw_node("notification"),
	    &e)) != 0) {
		cbl_msg_free(msg);
		goto out;
	}
	error = cbl_notify(fam, group_idx, msg);
out:
	cbl_ybuf_free(&c);
	free(b);
	return (error);
}

int
cbl_msg_ynotif(const cbl_msg *msg, struct cbl_ynotif *nt, cbl_yarena *a)
{
	struct cblink_notification e;
	const struct cbl_ynode *ev = event_node();
	const uint8_t *p, *end;
	uint64_t v;
	int major, error;

	if (msg == NULL || nt == NULL || a == NULL || ev == NULL)
		return (EINVAL);
	memset(nt, 0, sizeof(*nt));
	if ((error = cbl_msg_ydecode(msg, cbl_fw_node("notification"), &e, a,
	    CBL_YD_STRICT, NULL, 0)) != 0)
		return (error);
	if (e.event.p == NULL)
		return (ENOENT);
	p = e.event.p;
	end = p + e.event.len;
	/* {delta: content}: one item. */
	if (get_head(&p, end, &major, &v) != 0 || major != 5 || v != 1 ||
	    get_head(&p, end, &major, &v) != 0 || major > 1 || v > INT64_MAX)
		return (EINVAL);
	nt->sid = ev->sid + (major == 0 ? v : ~v);
	nt->event_time = e.event_time;
	nt->content = p;
	nt->len = (size_t)(end - p);
	return (0);
}

int
cbl_yserver_add(cbl_ctx *ctx, const struct cbl_yserver *srv, void *arg)
{
	struct cbl_yserved *v;
	cbl_family *fam;
	int error;

	if (ctx == NULL || srv == NULL || srv->schema == NULL ||
	    (srv->nhandler > 0 && srv->handler == NULL) ||
	    (srv->nsidfile > 0 && srv->sidfile == NULL))
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

/* {cblink:action: {target: the instance-identifier}}: what an action
 * acts on, beside its input. */
int
cbl_msg_put_yaction(cbl_msg *msg, const void *target, size_t len)
{
	struct cblink_action ac;

	if (msg == NULL || target == NULL || len == 0)
		return (EINVAL);
	ac.target.p = target;
	ac.target.len = len;
	return (cbl_msg_put_ynode(msg, cbl_fw_node("action"), &ac));
}

int
cbl_yserver_threads(cbl_ctx *ctx, bool on)
{

	if (ctx == NULL)
		return (EINVAL);
	atomic_store(&ctx->ythreads, on);
	return (0);
}

/* A GET's targets: the cblink:get structure, each a SID. */
int
cbl_msg_put_yget(cbl_msg *msg, const uint64_t *sids, size_t n)
{

	return (cbl_msg_put_yget_xpath(msg, sids, n, NULL));
}

/* The same, what xpath selects of them alone (NULL: all of it). */
int
cbl_msg_put_yget_xpath(cbl_msg *msg, const uint64_t *sids, size_t n,
    const char *xpath)
{
	struct cblink_get g = { 0 };
	struct cbl_bytes *t;
	uint8_t *b;
	int error;

	if (msg == NULL || (sids == NULL && n > 0))
		return (EINVAL);
	if (n == 0 && xpath == NULL)
		return (0);
	g.xpath_filter = xpath;
	if ((t = calloc(n > 0 ? n : 1, sizeof(*t))) == NULL ||
	    (b = calloc(n > 0 ? n : 1, 9)) == NULL) {
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
