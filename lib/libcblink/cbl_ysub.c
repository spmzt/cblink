/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Family 1's subscriptions: RFC 8639's dynamic subscriptions and RFC
 * 8641's YANG-Push, periodic and on-change, each a push stream
 * (SUBSCRIBE).
 *
 *	open	{SID(establish-subscription): input}, as an rpc's: the
 *		NETCONF stream (stream, stream-xpath-filter) or the
 *		operational datastore (datastore, datastore-xpath-filter,
 *		periodic {period, anchor-time}, or on-change
 *		{dampening-period, sync-on-start, excluded-change});
 *		stop-time.  What else
 *		the input has is refused, by name.
 *	accept	{SID(establish-subscription): output}, the id.
 *	data	a cblink:notification each, as group "notify" carries
 *		them: an event of the stream, a push-update {id,
 *		datastore-contents, incomplete-update}, or a
 *		push-change-update {id, datastore-changes: {yang-patch}}.
 *
 * The nodes are found by name in the tables of the server that has
 * ietf-subscribed-notifications; a datastore's needs ietf-yang-push and
 * ietf-datastores there too.  A periodic subscription has a thread of
 * its own that reads, at each period from its anchor, the top-level
 * nodes the filter's paths begin with (all of them, where it cannot
 * tell) through their get handlers, on a request of the stream's
 * connection (so a handler sees the subscriber as the peer), and pushes
 * what the filter selects.  On-change is a read at each dampening
 * period (a second at least) compared with the last one: what changed,
 * a YANG Patch (RFC 8072), its targets RFC 8040's api-paths.  A
 * stop-time is kept by the same thread.  A
 * record that does not fit in the stream's credit is left out and the
 * subscription suspended (RFC 8639's subscription-suspended), resumed
 * once the subscriber has read.  A subscription ends by
 * its stream, closed when stop-time comes, on delete or kill; a
 * dynamic subscription's end is its transport's (RFC 8639 section
 * 2.4.2), so no state notification is sent.
 */

#include <sys/param.h>

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cbl_data.h"
#include "cbl_dimpl.h"
#include "cbl_impl.h"
#include "cbl_schema.h"
#include "cbl_yimpl.h"

/* The nodes a server's tables have for subscriptions. */
struct ynodes {
	const struct cbl_yserver *srv;
	const struct cbl_ynode	*rpc, *in, *out, *out_id;
	/* ietf-yang-push's push-update, its members; NULL: none. */
	const struct cbl_ynode	*pu, *pu_id, *pu_dc, *pu_inc;
	/* Its push-change-update and the YANG Patch in it (on-change,
	 * RFC 8641's feature); NULL: none. */
	const struct cbl_ynode	*pcu, *pcu_id, *pcu_dc, *yp, *yp_pid, *ed,
				*ed_id, *ed_op, *ed_target, *ed_value;
	uint64_t		 operational;
	/* The state notifications; modify-subscription's input; the
	 * output's replay-start-time-revision (NULL: none of them). */
	const struct cbl_ynode	*n_susp, *n_resumed, *n_modified, *n_replayed,
				*mod_in, *out_rev;
	uint64_t		 unsupportable;	/* a suspension's reason */
};

/* A record held while a replay is sent, in the order it came. */
struct yrec {
	uint64_t		 sid;
	uint8_t			*p;
	size_t			 len;
	struct timespec		 when;
	bool			 has_when;
};

struct cbl_ysub {
	TAILQ_ENTRY(cbl_ysub)	 link;
	cbl_ctx			*ctx;
	cbl_stream		*s;		/* a reference */
	struct ynodes		 y;
	uint32_t		 id;
	char			*stream;	/* or NULL: a datastore's */
	uint64_t		 datastore;
	char			*xpath;
	uint32_t		 period;	/* centiseconds */
	char			*anchor_s, *stop_s;
	struct timespec		 anchor, stop;
	bool			 has_stop;
	uint64_t		*top;		/* what a period reads */
	size_t			 ntop;
	/* On-change: read every period (the dampening period, a second
	 * at least), its changes pushed; those of the change types
	 * excluded (1 << CBL_DOP_*) left out; what was read last. */
	bool			 onchange, sync;
	uint32_t		 dampening;
	unsigned		 excluded_ops;
	cbl_dtree		*last;
	uint64_t		 patches;
	char			*receiver;
	_Atomic uint64_t	 sent, excluded;
	/* Out of credit: records left out until the subscriber reads
	 * again; on-change pushes everything again then (resync). */
	_Atomic bool		 suspended, resync;
	/* Replay (replay-start-time): live records held meanwhile. */
	bool			 has_replay;
	struct timespec		 replay_from;
	bool			 replaying;	/* ysublock's */
	struct yrec		*held;
	size_t			 nheld, capheld;
	/* What a modify replaced, freed with the subscription: a thread
	 * may be reading it still. */
	void			**retired;
	size_t			 nretired;
	/* ysublock's: a thread runs it; push now (resync, modify); its
	 * first read done; told of a change since its last read. */
	bool			 dead, listed, threaded, kick, synced, dirty;
	/* Whom it was made for: NACM's to say what it is sent. */
	char			*user;
	bool			 recovery;
	int			 refs;
	pthread_cond_t		 cv;
};

static bool	selects(const struct cbl_ysub *, const struct cbl_ynode *,
		    const uint8_t *, size_t);
static bool	ts_before(const struct timespec *, const struct timespec *);

static const struct cbl_ymodule *
mod_named(const struct cbl_yschema *s, const char *name)
{

	for (uint32_t i = 0; i < s->nmod; i++)
		if (strcmp(s->mod[i]->name, name) == 0)
			return (s->mod[i]);
	return (NULL);
}

static const struct cbl_ynode *
top_named(const struct cbl_ymodule *m, const char *name)
{

	for (uint32_t i = 0; m != NULL && i < m->ntop; i++)
		if (strcmp(m->top[i]->name, name) == 0)
			return (m->top[i]);
	return (NULL);
}

static const struct cbl_ynode *
child_named(const struct cbl_ynode *n, const char *name)
{

	for (uint32_t i = 0; n != NULL && i < n->nchild; i++)
		if (strcmp(n->child[i]->name, name) == 0)
			return (n->child[i]);
	return (NULL);
}

static const struct cbl_ynode *
child_kind(const struct cbl_ynode *n, int kind)
{

	for (uint32_t i = 0; n != NULL && i < n->nchild; i++)
		if (n->child[i]->kind == kind)
			return (n->child[i]);
	return (NULL);
}

/* The first server whose tables have establish-subscription. */
static bool
nodes(cbl_ctx *ctx, struct ynodes *y)
{
	const struct cbl_yschema *s;
	const struct cbl_ymodule *m;
	const struct cbl_yident *id;

	memset(y, 0, sizeof(*y));
	pthread_rwlock_rdlock(&ctx->famlock);
	for (size_t i = 0; i < ctx->nysrv && y->rpc == NULL; i++) {
		s = ctx->ysrv[i].srv->schema;
		if ((y->rpc = top_named(mod_named(s,
		    "ietf-subscribed-notifications"),
		    "establish-subscription")) != NULL)
			y->srv = ctx->ysrv[i].srv;
	}
	pthread_rwlock_unlock(&ctx->famlock);
	if (y->rpc == NULL)
		return (false);
	s = y->srv->schema;
	y->in = child_kind(y->rpc, CBL_YN_INPUT);
	y->out = child_kind(y->rpc, CBL_YN_OUTPUT);
	y->out_id = child_named(y->out, "id");
	if (y->in == NULL || y->out_id == NULL)
		return (false);
	if ((y->pu = top_named(mod_named(s, "ietf-yang-push"),
	    "push-update")) != NULL) {
		y->pu_id = child_named(y->pu, "id");
		y->pu_dc = child_named(y->pu, "datastore-contents");
		y->pu_inc = child_named(y->pu, "incomplete-update");
		if (y->pu_id == NULL || y->pu_dc == NULL)
			y->pu = NULL;
	}
	if ((y->pcu = top_named(mod_named(s, "ietf-yang-push"),
	    "push-change-update")) != NULL) {
		y->pcu_id = child_named(y->pcu, "id");
		y->pcu_dc = child_named(y->pcu, "datastore-changes");
		y->yp = child_named(y->pcu_dc, "yang-patch");
		y->yp_pid = child_named(y->yp, "patch-id");
		y->ed = child_named(y->yp, "edit");
		y->ed_id = child_named(y->ed, "edit-id");
		y->ed_op = child_named(y->ed, "operation");
		y->ed_target = child_named(y->ed, "target");
		y->ed_value = child_named(y->ed, "value");
		if (y->pcu_id == NULL || y->ed_id == NULL || y->ed_op == NULL ||
		    y->ed_target == NULL || y->ed_value == NULL ||
		    y->yp_pid == NULL)
			y->pcu = NULL;
	}
	for (uint32_t i = 0; i < s->nident; i++) {
		id = &s->ident[i];
		if (strcmp(id->name, "operational") == 0 &&
		    strcmp(id->module->name, "ietf-datastores") == 0)
			y->operational = id->sid;
		else if (strcmp(id->name, "unsupportable-volume") == 0 &&
		    strcmp(id->module->name,
		    "ietf-subscribed-notifications") == 0)
			y->unsupportable = id->sid;
	}
	m = mod_named(s, "ietf-subscribed-notifications");
	y->n_susp = top_named(m, "subscription-suspended");
	y->n_resumed = top_named(m, "subscription-resumed");
	y->n_modified = top_named(m, "subscription-modified");
	y->n_replayed = top_named(m, "replay-completed");
	y->mod_in = child_kind(top_named(m, "modify-subscription"),
	    CBL_YN_INPUT);
	y->out_rev = child_named(y->out, "replay-start-time-revision");
	return (true);
}

/* yang:date-and-time, into ts; false: it is none. */
static bool
datetime(const char *s, struct timespec *ts)
{
	struct tm tm;
	int y, mo, d, h, mi, sec, n = 0, oh, om;
	long ns = 0, f = 100000000L;
	time_t t;

	if (sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d%n", &y, &mo, &d, &h, &mi, &sec,
	    &n) != 6 || n != 19)
		return (false);
	s += n;
	if (*s == '.')
		for (s++; isdigit((unsigned char)*s); s++, f /= 10)
			ns += (*s - '0') * f;
	memset(&tm, 0, sizeof(tm));
	tm.tm_year = y - 1900;
	tm.tm_mon = mo - 1;
	tm.tm_mday = d;
	tm.tm_hour = h;
	tm.tm_min = mi;
	tm.tm_sec = sec;
	if ((t = timegm(&tm)) == -1)
		return (false);
	if (*s == 'Z' || *s == 'z')
		s++;
	else if ((*s == '+' || *s == '-') && sscanf(s + 1, "%2d:%2d", &oh,
	    &om) == 2 && strlen(s) == 6) {
		t += (*s == '+' ? -1 : 1) * (oh * 3600 + om * 60);
		s += 6;
	} else
		return (false);
	if (*s != '\0')
		return (false);
	ts->tv_sec = t;
	ts->tv_nsec = ns;
	return (true);
}

/*
 * The top-level nodes a period reads: those the filter's paths begin
 * with ("/module:name"), or every one the server reads where a path
 * does not begin so.
 */
static int
targets(struct cbl_ysub *sub)
{
	const struct cbl_yserver *srv = sub->y.srv;
	const struct cbl_ynode *n;
	char *x, *p, *e, *mod, *name;
	bool all = sub->xpath == NULL;
	size_t cap = 0;
	int depth;

	sub->ntop = 0;
	if ((x = sub->xpath != NULL ? strdup(sub->xpath) : NULL) == NULL &&
	    sub->xpath != NULL)
		return (ENOMEM);
	/* Each path of a union, at its top level. */
	for (p = x; !all && p != NULL; p = e) {
		for (e = p, depth = 0; *e != '\0'; e++) {
			if (*e == '[' || *e == '(')
				depth++;
			else if ((*e == ']' || *e == ')') && depth > 0)
				depth--;
			else if ((*e == '\'' || *e == '"') &&
			    strchr(e + 1, *e) != NULL)
				e = strchr(e + 1, *e);
			else if (*e == '|' && depth == 0)
				break;
		}
		e = *e == '|' ? (*e = '\0', e + 1) : NULL;
		while (isspace((unsigned char)*p))
			p++;
		if (p[0] != '/' || p[1] == '/') {
			all = true;
			break;
		}
		mod = p + 1;
		name = mod + strcspn(mod, ":/[ ");
		if (*name != ':') {
			all = true;
			break;
		}
		*name++ = '\0';
		name[strcspn(name, "/[ ")] = '\0';
		if ((n = top_named(mod_named(srv->schema, mod), name)) == NULL ||
		    !cbl_yis_top_data(n)) {
			all = true;
			break;
		}
		if (sub->ntop == cap) {
			uint64_t *v = reallocarray(sub->top, cap + 4,
			    sizeof(*v));

			if (v == NULL) {
				free(x);
				return (ENOMEM);
			}
			sub->top = v;
			cap += 4;
		}
		sub->top[sub->ntop++] = n->sid;
	}
	free(x);
	if (!all)
		return (0);
	free(sub->top);
	sub->top = NULL;
	sub->ntop = cap = 0;
	for (uint32_t i = 0; i < srv->nhandler; i++) {
		n = cbl_yschema_node(srv->schema, srv->handler[i].sid);
		if (srv->handler[i].get == NULL || n == NULL ||
		    !cbl_yis_top_data(n))
			continue;
		if (sub->ntop == cap) {
			uint64_t *v = reallocarray(sub->top, cap + 16,
			    sizeof(*v));

			if (v == NULL)
				return (ENOMEM);
			sub->top = v;
			cap += 16;
		}
		sub->top[sub->ntop++] = n->sid;
	}
	return (0);
}

static void
sub_rele(struct cbl_ysub *sub)
{

	pthread_mutex_lock(&sub->ctx->ysublock);
	if (--sub->refs > 0) {
		pthread_mutex_unlock(&sub->ctx->ysublock);
		return;
	}
	pthread_mutex_unlock(&sub->ctx->ysublock);
	cbl_stream_rele(sub->s);
	cbl_dtree_free(sub->last);
	for (size_t i = 0; i < sub->nheld; i++)
		free(sub->held[i].p);
	free(sub->held);
	for (size_t i = 0; i < sub->nretired; i++)
		free(sub->retired[i]);
	free(sub->retired);
	pthread_cond_destroy(&sub->cv);
	free(sub->stream);
	free(sub->xpath);
	free(sub->anchor_s);
	free(sub->stop_s);
	free(sub->top);
	free(sub->receiver);
	free(sub->user);
	free(sub);
}

/* With ysublock held: out of the list, its thread woken to end. */
static void
sub_end(struct cbl_ysub *sub)
{

	sub->dead = true;
	if (sub->listed) {
		TAILQ_REMOVE(&sub->ctx->ysubs, sub, link);
		sub->listed = false;
	}
	pthread_cond_broadcast(&sub->cv);
}

/*
 * One record on the stream, its event-time when (NULL: now).  One that
 * does not fit in the credit is left out and the subscription
 * suspended; while it is, records are left out too.  A state
 * notification (state) goes whether it is or not; EAGAIN when it does
 * not fit.
 */
static int
send_at(struct cbl_ysub *sub, uint64_t sid, const uint8_t *content,
    size_t len, const struct timespec *when, bool state)
{
	cbl_msg *m;
	int error;

	if (!state && atomic_load(&sub->suspended)) {
		atomic_fetch_add(&sub->excluded, 1);
		return (0);
	}
	if ((error = cbl_stream_msg_new(sub->s, &m)) != 0)
		return (error);
	if ((error = cbl_ynotif_put_at(m, sid, content, len, when)) != 0) {
		cbl_msg_free(m);
		return (error);
	}
	if ((error = cbl_stream_send(sub->s, m)) == EAGAIN) {
		cbl_msg_free(m);
		if (state)
			return (EAGAIN);
		atomic_fetch_add(&sub->excluded, 1);
		atomic_store(&sub->suspended, true);
		return (0);
	}
	if (error == 0)
		atomic_fetch_add(&sub->sent, 1);
	return (error);
}

/* Whether an event of the stream, by its notification's SID, may go to
 * the subscriber (NACM's read of it). */
static bool
event_ok(struct cbl_ysub *sub, uint64_t sid)
{
	const struct cbl_ynode *n;

	if (sub->stream == NULL ||
	    (n = cbl_yschema_node(sub->y.srv->schema, sid)) == NULL)
		return (true);
	return (cbl_ynacm_notif(sub->ctx, cbl_stream_conn(sub->s),
	    &(struct cbl_ywho){ sub->user, sub->recovery }, n));
}

static int
send_record(struct cbl_ysub *sub, uint64_t sid, const uint8_t *content,
    size_t len)
{

	return (send_at(sub, sid, content, len, NULL, false));
}

/*
 * A state notification n of the subscription (RFC 8639 section 2.7):
 * its id, a reason (an identity's SID, 0: none) and, for
 * subscription-modified, what the subscription is now.
 */
static int
send_state(struct cbl_ysub *sub, const struct cbl_ynode *n, uint64_t reason)
{
	const struct cbl_ynode *c, *g;
	struct cbl_ybuf b = { 0 };
	cbl_dtree *t;
	cbl_dnode *dn, *dc;
	const char *s;
	uint32_t u;
	int error;

	if (n == NULL)
		return (0);
	if ((t = cbl_dtree_new(sub->y.srv->schema)) == NULL)
		return (ENOMEM);
	if ((error = cbl_dnode_add(cbl_dtree_root(t), n, NULL, &dn)) == 0 &&
	    (c = child_named(n, "id")) != NULL)
		error = cbl_dnode_add(dn, c, &sub->id, NULL);
	if (error == 0 && reason != 0 && (c = child_named(n, "reason")) !=
	    NULL)
		error = cbl_dnode_add(dn, c, &reason, NULL);
	if (error == 0 && n == sub->y.n_modified) {
		if (sub->stream != NULL &&
		    (c = child_named(n, "stream")) != NULL &&
		    (error = cbl_dnode_add(dn, c, &sub->stream, NULL)) == 0 &&
		    (s = sub->xpath) != NULL &&
		    (c = child_named(n, "stream-xpath-filter")) != NULL)
			error = cbl_dnode_add(dn, c, &s, NULL);
		if (error == 0 && sub->stream == NULL &&
		    (c = child_named(n, "datastore")) != NULL &&
		    (error = cbl_dnode_add(dn, c, &sub->datastore, NULL)) ==
		    0 && (s = sub->xpath) != NULL &&
		    (c = child_named(n, "datastore-xpath-filter")) != NULL)
			error = cbl_dnode_add(dn, c, &s, NULL);
		if (error == 0 && (s = sub->stop_s) != NULL &&
		    (c = child_named(n, "stop-time")) != NULL)
			error = cbl_dnode_add(dn, c, &s, NULL);
		if (error == 0 && sub->stream == NULL && sub->onchange &&
		    (g = child_named(n, "on-change")) != NULL &&
		    (error = cbl_dnode_add(dn, g, NULL, &dc)) == 0 &&
		    (c = child_named(g, "dampening-period")) != NULL)
			error = cbl_dnode_add(dc, c, &sub->dampening, NULL);
		else if (error == 0 && sub->stream == NULL &&
		    (g = child_named(n, "periodic")) != NULL &&
		    (error = cbl_dnode_add(dn, g, NULL, &dc)) == 0 &&
		    (c = child_named(g, "period")) != NULL) {
			u = sub->period;
			error = cbl_dnode_add(dc, c, &u, NULL);
			if (error == 0 && (s = sub->anchor_s) != NULL &&
			    (c = child_named(g, "anchor-time")) != NULL)
				error = cbl_dnode_add(dc, c, &s, NULL);
		}
	}
	if (error == 0 && (error = cbl_dnode_encode(dn, &b)) == 0)
		error = send_at(sub, n->sid, b.p, b.len, NULL, true);
	cbl_ybuf_free(&b);
	cbl_dtree_free(t);
	return (error);
}

static int
buf_put(struct cbl_ybuf *b, const void *p, size_t n)
{
	uint8_t *q;
	size_t cap;

	if (b->len + n > b->cap) {
		for (cap = b->cap > 0 ? b->cap : 256; cap < b->len + n;
		    cap *= 2)
			;
		if ((q = realloc(b->p, cap)) == NULL)
			return (ENOMEM);
		b->p = q;
		b->cap = cap;
	}
	memcpy(b->p + b->len, p, n);
	b->len += n;
	return (0);
}

/* A CBOR head of major type major (4: an array, 5: a map). */
static int
buf_head(struct cbl_ybuf *b, uint8_t major, uint64_t v)
{
	uint8_t h[9];
	size_t n;

	n = cbl_ycbor_int(h, (int64_t)v);
	h[0] |= (uint8_t)(major << 5);
	return (buf_put(b, h, n));
}

static int
buf_int(struct cbl_ybuf *b, int64_t v)
{
	uint8_t h[9];

	return (buf_put(b, h, cbl_ycbor_int(h, v)));
}

/* A text string. */
static int
buf_text(struct cbl_ybuf *b, const char *t)
{
	int error;

	if ((error = buf_head(b, 3, strlen(t))) != 0)
		return (error);
	return (buf_put(b, t, strlen(t)));
}

/*
 * What the filter selects of the nodes read, a tree of its own (NULL:
 * none read); *incomplete where a read or the filter failed.
 */
static cbl_dtree *
read_filtered(struct cbl_ysub *sub, bool *incomplete)
{
	struct cbl_req r;
	cbl_dtree *t = NULL, *ft = NULL;
	char why[160];

	*incomplete = false;
	memset(&r, 0, sizeof(r));
	r.conn = cbl_stream_conn(sub->s);
	r.user = sub->user;
	r.recovery = sub->recovery;
	atomic_init(&r.refs, 1);
	if (cbl_yread_tree(&r, sub->top, sub->ntop, &t, incomplete) != 0)
		*incomplete = true;
	free(r.err_msg);
	/* What the subscriber may not read is no part of it. */
	if (t != NULL && cbl_ynacm_read(sub->ctx, r.conn, &(struct cbl_ywho){
	    sub->user, sub->recovery }, t) != 0)
		*incomplete = true;
	if (t == NULL || sub->xpath == NULL)
		return (t);
	ft = cbl_dtree_filter_xpath(t, sub->xpath, why, sizeof(why));
	if (ft == NULL)
		*incomplete = true;
	cbl_dtree_free(t);
	return (ft);
}

/* A node's value into anydata base's map: {delta: value}, a list's
 * entry or a leaf-list's value as a list or leaf-list of one. */
static int
put_member(struct cbl_ybuf *b, const cbl_dnode *n, uint64_t base)
{
	const struct cbl_ynode *sn = cbl_dnode_schema(n);
	struct cbl_ybuf v = { 0 };
	int error;

	if ((error = cbl_dnode_encode(n, &v)) == 0 &&
	    (error = buf_int(b, (int64_t)(sn->sid - base))) == 0 &&
	    ((sn->kind != CBL_YN_LIST && sn->kind != CBL_YN_LEAFLIST) ||
	    (error = buf_head(b, 4, 1)) == 0))
		error = buf_put(b, v.p, v.len);
	cbl_ybuf_free(&v);
	return (error);
}

/*
 * A push-update of root's nodes: {id, datastore-contents: {delta:
 * value}, incomplete-update where a read failed}.
 */
static int
push_update(struct cbl_ysub *sub, const cbl_dnode *root, bool incomplete)
{
	const struct ynodes *y = &sub->y;
	struct cbl_ybuf dc = { 0 }, c = { 0 };
	const cbl_dnode *n;
	size_t count = 0;
	int error;

	/* A member a node; a list's entries, one after another, one. */
	for (n = root != NULL ? cbl_dnode_first(root) : NULL; n != NULL;
	    n = cbl_dnode_next(n))
		if (cbl_dnode_prev(n) == NULL || cbl_dnode_schema(
		    cbl_dnode_prev(n)) != cbl_dnode_schema(n))
			count++;
	error = buf_head(&dc, 5, count);
	for (n = root != NULL ? cbl_dnode_first(root) : NULL; error == 0 &&
	    n != NULL; n = cbl_dnode_next(n)) {
		const struct cbl_ynode *sn = cbl_dnode_schema(n);
		struct cbl_ybuf v = { 0 };
		const cbl_dnode *e;
		size_t k = 0;

		if (sn->kind != CBL_YN_LIST && sn->kind != CBL_YN_LEAFLIST) {
			error = put_member(&dc, n, y->pu_dc->sid);
			continue;
		}
		for (e = n; e != NULL && cbl_dnode_schema(e) == sn;
		    e = cbl_dnode_next(e))
			k++;
		if ((error = buf_int(&dc, (int64_t)(sn->sid -
		    y->pu_dc->sid))) != 0 ||
		    (error = buf_head(&dc, 4, k)) != 0)
			break;
		for (; error == 0; n = cbl_dnode_next(n)) {
			if ((error = cbl_dnode_encode(n, &v)) == 0)
				error = buf_put(&dc, v.p, v.len);
			cbl_ybuf_free(&v);
			memset(&v, 0, sizeof(v));
			if (--k == 0)
				break;
		}
	}
	incomplete = incomplete && y->pu_inc != NULL;
	if (error == 0 && (error = buf_head(&c, 5, incomplete ? 3 : 2)) == 0 &&
	    (error = buf_int(&c, (int64_t)(y->pu_id->sid - y->pu->sid))) == 0 &&
	    (error = buf_int(&c, (int64_t)sub->id)) == 0 &&
	    (error = buf_int(&c, (int64_t)(y->pu_dc->sid - y->pu->sid))) == 0)
		error = buf_put(&c, dc.p, dc.len);
	if (error == 0 && incomplete &&
	    (error = buf_int(&c, (int64_t)(y->pu_inc->sid - y->pu->sid))) == 0)
		error = buf_put(&c, "\xf6", 1);		/* empty: null */
	if (error == 0)
		error = send_record(sub, y->pu->sid, c.p, c.len);
	cbl_ybuf_free(&dc);
	cbl_ybuf_free(&c);
	return (error);
}

/* The periodic push: what the filter selects, now. */
static int
push(struct cbl_ysub *sub)
{
	cbl_dtree *t;
	bool incomplete;
	int error;

	t = read_filtered(sub, &incomplete);
	error = push_update(sub, t != NULL ? cbl_dtree_root(t) : NULL,
	    incomplete);
	cbl_dtree_free(t);
	return (error);
}

/* RFC 8040's api-path of n, keys percent-encoded (section 3.5.3). */
static int
api_path(const cbl_dnode *n, struct cbl_ybuf *b)
{
	const cbl_dnode *v[64], *p;
	const struct cbl_ynode *sn, *psn, *kn;
	const struct cbl_yschema *s;
	char *str;
	size_t nv = 0;
	int error = 0;

	for (p = n; p != NULL && cbl_dnode_schema(p) != NULL; p =
	    cbl_dnode_parent(p)) {
		if (nv == nitems(v))
			return (ELOOP);
		v[nv++] = p;
	}
	while (error == 0 && nv-- > 0) {
		sn = cbl_dnode_schema(v[nv]);
		psn = nv + 1 < 64 && cbl_dnode_parent(v[nv]) != NULL ?
		    cbl_dnode_schema(cbl_dnode_parent(v[nv])) : NULL;
		s = sn->module->schema;
		if ((error = buf_put(b, "/", 1)) != 0)
			break;
		if (psn == NULL || psn->module != sn->module) {
			if ((error = buf_put(b, sn->module->name,
			    strlen(sn->module->name))) != 0 ||
			    (error = buf_put(b, ":", 1)) != 0)
				break;
		}
		if ((error = buf_put(b, sn->name, strlen(sn->name))) != 0)
			break;
		for (uint16_t k = 0; error == 0 && (sn->kind == CBL_YN_LIST ?
		    k < sn->nkeys : sn->kind == CBL_YN_LEAFLIST && k < 1);
		    k++) {
			const void *val;

			if (sn->kind == CBL_YN_LIST) {
				const cbl_dnode *kd;

				kn = sn->child[sn->keys[k]];
				if ((kd = cbl_dnode_child(v[nv], kn)) == NULL)
					return (EINVAL);
				val = cbl_dnode_value(kd);
			} else {
				kn = sn;
				val = cbl_dnode_value(v[nv]);
			}
			if ((error = cbl_d_vstring(s, kn->type, val, &str)) !=
			    0)
				break;
			error = buf_put(b, k == 0 ? "=" : ",", 1);
			for (const char *c = str; error == 0 && *c != '\0';
			    c++) {
				char pct[4];

				if (strchr(",/=%?#[] \"'", *c) != NULL ||
				    (unsigned char)*c < 0x20) {
					(void)snprintf(pct, sizeof(pct), "%%%02X",
					    (unsigned char)*c);
					error = buf_put(b, pct, 3);
				} else
					error = buf_put(b, c, 1);
			}
			free(str);
		}
	}
	return (error);
}

/* RFC 8641's change types, by the diff's operations. */
static const char *
change_type(int op)
{

	switch (op) {
	case CBL_DOP_CREATE:
		return ("create");
	case CBL_DOP_MERGE:
	case CBL_DOP_REPLACE:
		return ("replace");
	case CBL_DOP_REMOVE:
	case CBL_DOP_DELETE:
		return ("delete");
	case CBL_DOP_INSERT:
		return ("insert");
	case CBL_DOP_MOVE:
		return ("move");
	}
	return (NULL);
}

/* An enumeration's value by its name; -1: none. */
static int64_t
enum_value(const struct cbl_ynode *n, const char *name)
{

	for (uint32_t i = 0; n->type != NULL && i < n->type->nitems; i++)
		if (strcmp(n->type->items[i].name, name) == 0)
			return (n->type->items[i].value);
	return (-1);
}

/*
 * The edits of diff tree n's children into arr, a YANG Patch's edit
 * entries (RFC 8072): a node the diff made, merged or removed is one,
 * with what is below it; one of a type excluded is left out.
 */
static int
patch_edits(struct cbl_ysub *sub, const cbl_dnode *n, struct cbl_ybuf *arr,
    size_t *count)
{
	const struct ynodes *y = &sub->y;
	struct cbl_ybuf tgt = { 0 }, val = { 0 };
	const cbl_dnode *c;
	const char *type;
	char eid[24];
	int64_t opv;
	int op, error = 0;
	bool value;

	for (c = cbl_dnode_first(n); error == 0 && c != NULL;
	    c = cbl_dnode_next(c)) {
		op = cbl_dnode_op(c);
		if ((type = change_type(op)) == NULL) {
			error = patch_edits(sub, c, arr, count);
			continue;
		}
		if ((sub->excluded_ops & (1u << op)) != 0)
			continue;
		/* YANG Patch's operation: a change's type, a delete's. */
		if ((opv = enum_value(y->ed_op, type)) < 0)
			return (EINVAL);
		value = strcmp(type, "delete") != 0;
		if ((error = api_path(c, &tgt)) != 0 ||
		    (error = buf_put(&tgt, "", 1)) != 0)
			break;
		(void)snprintf(eid, sizeof(eid), "%zu", *count + 1);
		if ((error = buf_head(arr, 5, value ? 4 : 3)) == 0 &&
		    (error = buf_int(arr, (int64_t)(y->ed_id->sid -
		    y->ed->sid))) == 0 &&
		    (error = buf_text(arr, eid)) == 0 &&
		    (error = buf_int(arr, (int64_t)(y->ed_op->sid -
		    y->ed->sid))) == 0 &&
		    (error = buf_int(arr, opv)) == 0 &&
		    (error = buf_int(arr, (int64_t)(y->ed_target->sid -
		    y->ed->sid))) == 0 &&
		    (error = buf_text(arr, (const char *)tgt.p)) == 0 && value &&
		    (error = buf_int(arr, (int64_t)(y->ed_value->sid -
		    y->ed->sid))) == 0 &&
		    (error = buf_head(&val, 5, 1)) == 0 &&
		    (error = put_member(&val, c, y->ed_value->sid)) == 0)
			error = buf_put(arr, val.p, val.len);
		cbl_ybuf_free(&tgt);
		cbl_ybuf_free(&val);
		memset(&tgt, 0, sizeof(tgt));
		memset(&val, 0, sizeof(val));
		(*count)++;
	}
	cbl_ybuf_free(&tgt);
	return (error);
}

/*
 * On-change (RFC 8641 section 3.3): what the filter selects, read now,
 * compared with what was read last (cbl_dtree_diff()); its changes, a
 * YANG Patch, pushed as a push-change-update.  The first read is a
 * push-update with sync-on-start.  A read that failed is not compared:
 * what it missed would read as gone.
 */
static int
change_push(struct cbl_ysub *sub)
{
	const struct ynodes *y = &sub->y;
	struct cbl_ybuf arr = { 0 }, c = { 0 };
	cbl_dtree *t, *d;
	bool incomplete;
	size_t count = 0;
	char pid[24];
	int error = 0;

	if ((t = read_filtered(sub, &incomplete)) == NULL && !incomplete &&
	    (t = cbl_dtree_new(y->srv->schema)) == NULL)
		return (ENOMEM);
	/* A getter failed: nothing compared, read again at the next
	 * tick. */
	if (incomplete) {
		cbl_dtree_free(t);
		return (EAGAIN);
	}
	/* A resync (asked, or after a suspension): the whole of it. */
	if (atomic_exchange(&sub->resync, false) && sub->last != NULL) {
		cbl_dtree_free(sub->last);
		sub->last = NULL;
		error = push_update(sub, cbl_dtree_root(t), false);
		sub->last = t;
		return (error);
	}
	if (sub->last == NULL) {
		if (sub->sync)
			error = push_update(sub, cbl_dtree_root(t), false);
		sub->last = t;
		return (error);
	}
	if ((d = cbl_dtree_diff(sub->last, t)) == NULL) {
		cbl_dtree_free(t);
		return (errno == ENOMEM ? ENOMEM : 0);
	}
	error = patch_edits(sub, cbl_dtree_root(d), &arr, &count);
	cbl_dtree_free(d);
	cbl_dtree_free(sub->last);
	sub->last = t;
	if (error != 0 || count == 0) {
		cbl_ybuf_free(&arr);
		return (error);
	}
	/*
	 * {id, datastore-changes: {yang-patch: {patch-id, edit: [...]}}}:
	 * each map's keys deltas from its own node's SID.
	 */
	(void)snprintf(pid, sizeof(pid), "%ju", (uintmax_t)++sub->patches);
	if ((error = buf_head(&c, 5, 2)) == 0 &&
	    (error = buf_int(&c, (int64_t)(y->pcu_id->sid - y->pcu->sid))) ==
	    0 && (error = buf_int(&c, (int64_t)sub->id)) == 0 &&
	    (error = buf_int(&c, (int64_t)(y->pcu_dc->sid - y->pcu->sid))) ==
	    0 && (error = buf_head(&c, 5, 1)) == 0 &&
	    (error = buf_int(&c, (int64_t)(y->yp->sid - y->pcu_dc->sid))) ==
	    0 && (error = buf_head(&c, 5, 2)) == 0 &&
	    (error = buf_int(&c, (int64_t)(y->yp_pid->sid - y->yp->sid))) ==
	    0 && (error = buf_text(&c, pid)) == 0 &&
	    (error = buf_int(&c, (int64_t)(y->ed->sid - y->yp->sid))) == 0 &&
	    (error = buf_head(&c, 4, count)) == 0 &&
	    (error = buf_put(&c, arr.p, arr.len)) == 0)
		error = send_record(sub, y->pcu->sid, c.p, c.len);
	cbl_ybuf_free(&arr);
	cbl_ybuf_free(&c);
	return (error);
}

static void
ts_add_cs(struct timespec *ts, uint64_t cs)
{

	ts->tv_sec += (time_t)(cs / 100);
	ts->tv_nsec += (long)(cs % 100) * 10000000L;
	if (ts->tv_nsec >= 1000000000L) {
		ts->tv_sec++;
		ts->tv_nsec -= 1000000000L;
	}
}

static bool
ts_before(const struct timespec *a, const struct timespec *b)
{

	return (a->tv_sec < b->tv_sec || (a->tv_sec == b->tv_sec &&
	    a->tv_nsec < b->tv_nsec));
}

/* The first of anchor's periods not before now. */
static void
next_tick(const struct cbl_ysub *sub, const struct timespec *now,
    struct timespec *next)
{
	int64_t ds, k;

	*next = sub->anchor;
	if (!ts_before(next, now))
		return;
	ds = (int64_t)(now->tv_sec - sub->anchor.tv_sec) * 100 +
	    (now->tv_nsec - sub->anchor.tv_nsec) / 10000000L;
	k = ds / sub->period;
	ts_add_cs(next, (uint64_t)k * sub->period);
	while (ts_before(next, now))
		ts_add_cs(next, sub->period);
}

/* With ysublock: an on-change subscription that reads only what the
 * program tells the changes of. */
static bool
waits_told(const struct cbl_ysub *sub)
{
	size_t i, j;

	if (!sub->onchange || sub->ntop == 0)
		return (false);
	for (i = 0; i < sub->ntop; i++) {
		for (j = 0; j < sub->ctx->nytold; j++)
			if (sub->ctx->ytold[j] == sub->top[i])
				break;
		if (j == sub->ctx->nytold)
			return (false);
	}
	return (true);
}

/*
 * A periodic subscription's pushes, and its stop-time.  The first push
 * is at once without an anchor-time, else at the anchor's first period
 * from now; each next one a period on from the anchor, past the push.
 * An on-change one that waits to be told reads at its tick only once
 * told of a change, or asked to push the whole of it again.
 */
static void *
sub_thread(void *p)
{
	struct cbl_ysub *sub = p;
	struct timespec now, due, wake;
	bool stop = false;
	int error;

	pthread_mutex_lock(&sub->ctx->ysublock);
	(void)clock_gettime(CLOCK_REALTIME, &now);
	if (sub->anchor_s == NULL)
		due = now;
	else
		next_tick(sub, &now, &due);
	while (!sub->dead) {
		(void)clock_gettime(CLOCK_REALTIME, &now);
		if (sub->kick) {
			sub->kick = false;
			sub->dirty = true;
			due = now;
		}
		if (sub->has_stop && !ts_before(&now, &sub->stop)) {
			stop = true;
			break;
		}
		if (sub->period != 0 && sub->synced && !sub->dirty &&
		    !atomic_load(&sub->resync) && waits_told(sub)) {
			if (sub->has_stop)
				(void)pthread_cond_timedwait(&sub->cv,
				    &sub->ctx->ysublock, &sub->stop);
			else
				(void)pthread_cond_wait(&sub->cv,
				    &sub->ctx->ysublock);
			continue;
		}
		if (sub->period != 0 && !ts_before(&now, &due)) {
			sub->dirty = false;
			pthread_mutex_unlock(&sub->ctx->ysublock);
			error = sub->onchange ? change_push(sub) : push(sub);
			pthread_mutex_lock(&sub->ctx->ysublock);
			if (error == EPIPE)
				break;
			/* Read whole and compared; else read again, told or
			 * not. */
			if (error == 0)
				sub->synced = true;
			else if (sub->onchange)
				sub->dirty = true;
			(void)clock_gettime(CLOCK_REALTIME, &now);
			now.tv_nsec++;
			next_tick(sub, &now, &due);
			continue;
		}
		if (sub->period != 0) {
			wake = due;
			if (sub->has_stop && ts_before(&sub->stop, &wake))
				wake = sub->stop;
			(void)pthread_cond_timedwait(&sub->cv,
			    &sub->ctx->ysublock, &wake);
		} else if (sub->has_stop)
			(void)pthread_cond_timedwait(&sub->cv,
			    &sub->ctx->ysublock, &sub->stop);
		else
			(void)pthread_cond_wait(&sub->cv, &sub->ctx->ysublock);
	}
	if (stop)
		sub_end(sub);
	pthread_mutex_unlock(&sub->ctx->ysublock);
	if (stop)
		(void)cbl_stream_close(sub->s, 0, "stop-time reached");
	sub_rele(sub);
	return (NULL);
}

static void
sub_closed(cbl_stream *s __unused, int code __unused,
    const char *text __unused, void *arg)
{
	struct cbl_ysub *sub = arg;

	pthread_mutex_lock(&sub->ctx->ysublock);
	sub_end(sub);
	pthread_mutex_unlock(&sub->ctx->ysublock);
	sub_rele(sub);
}

/*
 * Credit again after a suspension: the subscriber told it was suspended
 * and is resumed (RFC 8639 sections 2.7.6, 2.7.7), what was left out
 * meanwhile counted as excluded; an on-change subscription pushes the
 * whole of it next, as a resync.
 */
static void
sub_writable(cbl_stream *s __unused, size_t credit __unused, void *arg)
{
	struct cbl_ysub *sub = arg;

	if (!atomic_load(&sub->suspended))
		return;
	if (send_state(sub, sub->y.n_susp, sub->y.unsupportable) != 0 ||
	    send_state(sub, sub->y.n_resumed, 0) != 0)
		return;
	atomic_store(&sub->resync, true);
	atomic_store(&sub->suspended, false);
	/* One waiting to be told reads at once. */
	pthread_mutex_lock(&sub->ctx->ysublock);
	pthread_cond_broadcast(&sub->cv);
	pthread_mutex_unlock(&sub->ctx->ysublock);
}

static const struct cbl_stream_cbs sub_cbs = {
	.on_close = sub_closed,
	.on_writable = sub_writable,
};

/* The input read into sub, by its leaves' names; 0, or said. */
static int
sub_input(cbl_req *req, struct cbl_ysub *sub, const cbl_dnode *din)
{
	const struct cbl_ynode *sn;
	const cbl_dnode *c, *pc;
	const void *v;
	const char *name;

	for (c = cbl_dnode_first(din); c != NULL; c = cbl_dnode_next(c)) {
		sn = cbl_dnode_schema(c);
		name = sn->name;
		v = cbl_dnode_value(c);
		if (strcmp(name, "stream") == 0) {
			if ((sub->stream = strdup(*(const char *const *)v)) ==
			    NULL)
				return (ENOMEM);
		} else if (strcmp(name, "datastore") == 0)
			sub->datastore = *(const uint64_t *)v;
		else if (strcmp(name, "stream-xpath-filter") == 0 ||
		    strcmp(name, "datastore-xpath-filter") == 0) {
			if ((sub->xpath = strdup(*(const char *const *)v)) ==
			    NULL)
				return (ENOMEM);
		} else if (strcmp(name, "stop-time") == 0) {
			if ((sub->stop_s = strdup(*(const char *const *)v)) ==
			    NULL)
				return (ENOMEM);
			if (!datetime(sub->stop_s, &sub->stop))
				return (cbl_ysay(req, EINVAL, sn->sid,
				    "invalid-value", "stop-time is no time"));
			sub->has_stop = true;
		} else if (strcmp(name, "replay-start-time") == 0) {
			if (!datetime(*(const char *const *)v,
			    &sub->replay_from))
				return (cbl_ysay(req, EINVAL, sn->sid,
				    "invalid-value",
				    "replay-start-time is no time"));
			sub->has_replay = true;
		} else if (strcmp(name, "periodic") == 0) {
			for (pc = cbl_dnode_first(c); pc != NULL;
			    pc = cbl_dnode_next(pc)) {
				sn = cbl_dnode_schema(pc);
				v = cbl_dnode_value(pc);
				if (strcmp(sn->name, "period") == 0)
					sub->period = *(const uint32_t *)v;
				else if (strcmp(sn->name, "anchor-time") == 0) {
					if ((sub->anchor_s = strdup(
					    *(const char *const *)v)) == NULL)
						return (ENOMEM);
					if (!datetime(sub->anchor_s,
					    &sub->anchor))
						return (cbl_ysay(req, EINVAL,
						    sn->sid, "invalid-value",
						    "anchor-time is no time"));
				}
			}
		} else if (strcmp(name, "on-change") == 0) {
			sub->onchange = true;
			sub->sync = true;
			for (pc = cbl_dnode_first(c); pc != NULL;
			    pc = cbl_dnode_next(pc)) {
				sn = cbl_dnode_schema(pc);
				v = cbl_dnode_value(pc);
				if (strcmp(sn->name, "dampening-period") == 0)
					sub->dampening = *(const uint32_t *)v;
				else if (strcmp(sn->name, "sync-on-start") == 0)
					sub->sync = *(const bool *)v;
				else if (strcmp(sn->name, "excluded-change") ==
				    0) {
					int64_t e = *(const int32_t *)v;
					const char *t = NULL;

					for (uint32_t k = 0; k < sn->type->nitems;
					    k++)
						if (sn->type->items[k].value ==
						    e)
							t = sn->type->items[k].
							    name;
					if (t == NULL)
						continue;
					if (strcmp(t, "create") == 0)
						sub->excluded_ops |=
						    1u << CBL_DOP_CREATE;
					else if (strcmp(t, "delete") == 0)
						sub->excluded_ops |=
						    1u << CBL_DOP_REMOVE |
						    1u << CBL_DOP_DELETE;
					else if (strcmp(t, "replace") == 0)
						sub->excluded_ops |=
						    1u << CBL_DOP_MERGE |
						    1u << CBL_DOP_REPLACE;
					else if (strcmp(t, "insert") == 0)
						sub->excluded_ops |=
						    1u << CBL_DOP_INSERT;
					else if (strcmp(t, "move") == 0)
						sub->excluded_ops |=
						    1u << CBL_DOP_MOVE;
				}
			}
		} else {
			char text[128];

			(void)snprintf(text, sizeof(text), "%s: not supported",
			    name);
			return (cbl_ysay(req, EOPNOTSUPP, sn->sid,
			    "operation-not-supported", text));
		}
	}
	return (0);
}

/* What the subscription asks for, checked; 0, or said. */
static int
sub_check(cbl_req *req, struct cbl_ysub *sub)
{
	const struct ynodes *y = &sub->y;
	struct timespec now;
	cbl_dtree *t, *ft;
	char why[160];
	int error;

	(void)clock_gettime(CLOCK_REALTIME, &now);
	if (sub->stream != NULL) {
		if (strcmp(sub->stream, "NETCONF") != 0)
			return (cbl_ysay(req, ENOENT, y->rpc->sid,
			    "invalid-value", "no such stream: NETCONF is the "
			    "one there is"));
		if (sub->period != 0)
			return (cbl_ysay(req, EINVAL, y->rpc->sid,
			    "invalid-value", "a stream's subscription has no "
			    "period"));
	} else {
		if (y->pu == NULL || y->operational == 0)
			return (cbl_ysay(req, EOPNOTSUPP, y->rpc->sid,
			    "operation-not-supported", "no datastore "
			    "subscriptions: ietf-yang-push is not served"));
		if (sub->datastore != y->operational)
			return (cbl_ysay(req, EOPNOTSUPP, y->rpc->sid,
			    "operation-not-supported", "the operational "
			    "datastore is the one subscribed to"));
		if (sub->onchange) {
			if (y->pcu == NULL)
				return (cbl_ysay(req, EOPNOTSUPP, y->rpc->sid,
				    "operation-not-supported", "no on-change: "
				    "ietf-yang-push's on-change is not on"));
			/* Changes are seen by reading: every dampening
			 * period, a second at least. */
			sub->period = sub->dampening > 100 ? sub->dampening :
			    100;
		}
		if (sub->period == 0)
			return (cbl_ysay(req, EINVAL, y->rpc->sid,
			    "invalid-value", "a datastore's subscription is "
			    "periodic: it needs a period"));
		/* A tenth of a second at least. */
		if (sub->period < 10)
			return (cbl_ysay(req, EINVAL, y->rpc->sid,
			    "invalid-value", "the period is 10 centiseconds "
			    "at least"));
		if (sub->anchor_s == NULL)
			sub->anchor = now;
	}
	if (sub->has_replay && (sub->stream == NULL ||
	    sub->ctx->yreplay == NULL))
		return (cbl_ysay(req, EOPNOTSUPP, y->rpc->sid,
		    "operation-not-supported", sub->stream == NULL ?
		    "replay is a stream's" : "nothing is kept to replay"));
	/* A stop-time gone by ends a replay, after it; else nothing. */
	if (sub->has_stop && !ts_before(&now, &sub->stop) &&
	    (!sub->has_replay || !ts_before(&sub->replay_from, &sub->stop)))
		return (cbl_ysay(req, EINVAL, y->rpc->sid, "invalid-value",
		    "stop-time has passed"));
	if (sub->xpath != NULL) {
		/* The filter, tried on nothing: a bad one refused now. */
		if ((t = cbl_dtree_new(y->srv->schema)) == NULL)
			return (ENOMEM);
		ft = cbl_dtree_filter_xpath(t, sub->xpath, why, sizeof(why));
		error = ft == NULL ? errno : 0;
		cbl_dtree_free(ft);
		cbl_dtree_free(t);
		if (error == ENOMEM)
			return (ENOMEM);
		if (error != 0)
			return (cbl_ysay(req, EINVAL, y->rpc->sid,
			    "invalid-value", why));
	}
	return (sub->stream == NULL ? targets(sub) : 0);
}

struct cbl_ysub_replay {
	struct cbl_ysub		*sub;
	struct yrec		*v;
	size_t			 n, cap;
	struct timespec		 oldest;
	bool			 has_oldest, live;
	int			 error;
};

static int
rec_add(struct yrec **vp, size_t *np, size_t *capp, uint64_t sid,
    const void *p, size_t len, const struct timespec *when)
{
	struct yrec *v;

	if (*np == *capp) {
		if ((v = reallocarray(*vp, *capp + 32, sizeof(*v))) == NULL)
			return (ENOMEM);
		*vp = v;
		*capp += 32;
	}
	v = &(*vp)[*np];
	if ((v->p = malloc(len > 0 ? len : 1)) == NULL)
		return (ENOMEM);
	memcpy(v->p, p, len);
	v->sid = sid;
	v->len = len;
	v->has_when = when != NULL;
	if (when != NULL)
		v->when = *when;
	(*np)++;
	return (0);
}

int
cbl_ysub_set_replay(cbl_ctx *ctx, cbl_ysub_replay_f *fn, void *arg)
{

	if (ctx == NULL)
		return (EINVAL);
	pthread_mutex_lock(&ctx->ysublock);
	ctx->yreplay = fn;
	ctx->yreplay_arg = arg;
	pthread_mutex_unlock(&ctx->ysublock);
	return (0);
}

int
cbl_ysub_replay_emit(struct cbl_ysub_replay *r, const struct cbl_ynode *n,
    const void *p, const struct timespec *when)
{
	struct cbl_ybuf b = { 0 };
	int error;

	if (r == NULL || n == NULL || p == NULL || n->kind != CBL_YN_NOTIF)
		return (EINVAL);
	if (r->live || (when != NULL && ts_before(when,
	    &r->sub->replay_from)))
		return (0);
	/* What the filter leaves out is not replayed either. */
	if ((error = cbl_yencode(n, p, &b)) == 0 && (r->sub->xpath == NULL ||
	    selects(r->sub, n, b.p, b.len)))
		error = rec_add(&r->v, &r->n, &r->cap, n->sid, b.p, b.len,
		    when);
	cbl_ybuf_free(&b);
	if (error != 0)
		r->error = error;
	return (error);
}

void
cbl_ysub_replay_oldest(struct cbl_ysub_replay *r,
    const struct timespec *oldest)
{

	if (r == NULL || oldest == NULL)
		return;
	r->oldest = *oldest;
	r->has_oldest = true;
}

/* From now on the subscription is told live, held until the replay is
 * sent. */
void
cbl_ysub_replay_live(struct cbl_ysub_replay *r)
{
	struct cbl_ysub *sub;

	if (r == NULL || r->live)
		return;
	sub = r->sub;
	pthread_mutex_lock(&sub->ctx->ysublock);
	sub->replaying = true;
	TAILQ_INSERT_TAIL(&sub->ctx->ysubs, sub, link);
	sub->listed = true;
	pthread_mutex_unlock(&sub->ctx->ysublock);
	r->live = true;
}

/*
 * After the accept: the replayed records with their times, then
 * replay-completed, then what came live meanwhile, in order.
 */
static void
replay_send(struct cbl_ysub *sub, struct cbl_ysub_replay *r)
{
	struct yrec rec;

	for (size_t i = 0; i < r->n; i++) {
		if (event_ok(sub, r->v[i].sid))
			(void)send_at(sub, r->v[i].sid, r->v[i].p, r->v[i].len,
			    r->v[i].has_when ? &r->v[i].when : NULL, false);
		free(r->v[i].p);
	}
	free(r->v);
	r->v = NULL;
	r->n = r->cap = 0;
	(void)send_state(sub, sub->y.n_replayed, 0);
	pthread_mutex_lock(&sub->ctx->ysublock);
	for (size_t i = 0;; i++) {
		if (i == sub->nheld) {
			sub->nheld = 0;
			sub->replaying = false;
			break;
		}
		rec = sub->held[i];
		pthread_mutex_unlock(&sub->ctx->ysublock);
		if (event_ok(sub, rec.sid))
			(void)send_at(sub, rec.sid, rec.p, rec.len, NULL,
			    false);
		free(rec.p);
		pthread_mutex_lock(&sub->ctx->ysublock);
	}
	pthread_mutex_unlock(&sub->ctx->ysublock);
}

/* With ysublock held: a thread for the periods and the stop-time. */
static int
sub_start(struct cbl_ysub *sub)
{
	pthread_t tid;

	if (sub->threaded)
		return (0);
	sub->refs++;
	if (pthread_create(&tid, NULL, sub_thread, sub) != 0) {
		sub->refs--;
		return (ENOMEM);
	}
	(void)pthread_detach(tid);
	sub->threaded = true;
	return (0);
}

/* The accept: the output, the id. */
static int
sub_accept_msg(cbl_req *req, const struct cbl_ysub *sub, const char *rev,
    cbl_msg **accp)
{
	const struct ynodes *y = &sub->y;
	cbl_dtree *t;
	cbl_dnode *dr, *dout;
	cbl_yarena *a;
	void *pout;
	int error;

	if ((t = cbl_dtree_new(y->srv->schema)) == NULL)
		return (ENOMEM);
	if ((a = cbl_yarena_new()) == NULL) {
		cbl_dtree_free(t);
		return (ENOMEM);
	}
	if ((pout = cbl_yarena_alloc(a, y->out->size)) == NULL)
		error = ENOMEM;
	else if ((error = cbl_dnode_add(cbl_dtree_root(t), y->rpc, NULL,
	    &dr)) == 0 &&
	    (error = cbl_dnode_add(dr, y->out, NULL, &dout)) == 0 &&
	    (error = cbl_dnode_add(dout, y->out_id, &sub->id, NULL)) == 0 &&
	    (rev == NULL || y->out_rev == NULL ||
	    (error = cbl_dnode_add(dout, y->out_rev, &rev, NULL)) == 0) &&
	    (error = cbl_dnode_to_struct(dout, pout, a)) == 0 &&
	    (error = cbl_msg_new(req->conn->ctx, CBL_YANG_FAMILY,
	    CBL_YCMD_SUBSCRIBE, 0, accp)) == 0 &&
	    (error = cbl_msg_put_ynode(*accp, y->out, pout)) != 0) {
		cbl_msg_free(*accp);
		*accp = NULL;
	}
	cbl_yarena_free(a);
	cbl_dtree_free(t);
	return (error);
}

int
cbl_ysub_open(cbl_req *req, const cbl_msg *msg, cbl_stream *s,
    void *arg __unused)
{
	cbl_ctx *ctx = req->conn->ctx;
	const char *subj;
	struct cbl_ysub_replay r;
	struct cbl_ysub *sub;
	cbl_dtree *t = NULL;
	cbl_dnode *dr, *din;
	cbl_msg *acc = NULL;
	cbl_yarena *a;
	const char *rev;
	void *pin;
	char why[160], revbuf[32];
	int error;

	if ((sub = calloc(1, sizeof(*sub))) == NULL)
		return (ENOMEM);
	sub->ctx = ctx;
	sub->refs = 1;
	pthread_cond_init(&sub->cv, NULL);
	sub->recovery = req->recovery;
	if (req->user != NULL && (sub->user = strdup(req->user)) == NULL) {
		sub_rele(sub);
		return (ENOMEM);
	}
	if (!nodes(ctx, &sub->y)) {
		sub_rele(sub);
		return (cbl_ysay(req, EOPNOTSUPP, 0, "operation-not-supported",
		    "no subscriptions: ietf-subscribed-notifications is not "
		    "served"));
	}
	if ((a = cbl_yarena_new()) == NULL) {
		sub_rele(sub);
		return (ENOMEM);
	}
	if ((pin = cbl_yarena_alloc(a, sub->y.in->size)) == NULL)
		error = ENOMEM;
	else if ((error = cbl_msg_ydecode(msg, sub->y.in, pin, a,
	    CBL_YD_STRICT, why, sizeof(why))) != 0)
		error = cbl_ysay(req, error == ENOENT ? EINVAL : error,
		    sub->y.rpc->sid, "bad-element", error == ENOENT ?
		    "no establish-subscription input" : why);
	else if ((t = cbl_dtree_new(sub->y.srv->schema)) == NULL)
		error = ENOMEM;
	else if ((error = cbl_dnode_add(cbl_dtree_root(t), sub->y.rpc, NULL,
	    &dr)) == 0 &&
	    (error = cbl_dnode_from_struct(dr, sub->y.in, pin, &din)) == 0 &&
	    (error = sub_input(req, sub, din)) == 0)
		error = sub_check(req, sub);
	cbl_dtree_free(t);
	cbl_yarena_free(a);
	if (error != 0) {
		sub_rele(sub);
		return (error);
	}
	subj = cbl_peer_subject(&req->conn->peer);
	if (subj != NULL && (sub->receiver = strdup(subj)) == NULL) {
		sub_rele(sub);
		return (ENOMEM);
	}
	pthread_mutex_lock(&ctx->ysublock);
	if (++ctx->ysubid == 0)
		ctx->ysubid = 1;
	sub->id = ctx->ysubid;
	pthread_mutex_unlock(&ctx->ysublock);
	cbl_stream_ref(s);
	sub->s = s;
	/* A replay: what is kept since its start, live after it. */
	memset(&r, 0, sizeof(r));
	r.sub = sub;
	rev = NULL;
	if (sub->has_replay) {
		error = ctx->yreplay(&sub->replay_from, &r, ctx->yreplay_arg);
		cbl_ysub_replay_live(&r);
		if (error == 0)
			error = r.error;
		if (error == 0 && r.has_oldest && ts_before(&sub->replay_from,
		    &r.oldest)) {
			struct tm tm;

			(void)gmtime_r(&r.oldest.tv_sec, &tm);
			(void)strftime(revbuf, sizeof(revbuf),
			    "%Y-%m-%dT%H:%M:%SZ", &tm);
			rev = revbuf;
		}
	}
	if (error != 0 ||
	    (error = sub_accept_msg(req, sub, rev, &acc)) != 0 ||
	    (error = cbl_stream_accept(s, acc, 0, &sub_cbs, sub)) != 0) {
		/* Not accepted: no callback will run, sub still ours. */
		for (size_t i = 0; i < r.n; i++)
			free(r.v[i].p);
		free(r.v);
		pthread_mutex_lock(&ctx->ysublock);
		sub_end(sub);
		pthread_mutex_unlock(&ctx->ysublock);
		sub_rele(sub);
		return (error);
	}
	if (sub->has_replay)
		replay_send(sub, &r);
	pthread_mutex_lock(&ctx->ysublock);
	if (!sub->listed && !sub->dead) {
		TAILQ_INSERT_TAIL(&ctx->ysubs, sub, link);
		sub->listed = true;
	}
	if ((sub->period != 0 || sub->has_stop) && sub_start(sub) != 0) {
		sub_end(sub);
		pthread_mutex_unlock(&ctx->ysublock);
		(void)cbl_stream_close(s, ENOMEM, "no thread for it");
		return (0);
	}
	pthread_mutex_unlock(&ctx->ysublock);
	return (0);
}

/* Whether the filter selects anything of notification n's content. */
static bool
selects(const struct cbl_ysub *sub, const struct cbl_ynode *n,
    const uint8_t *content, size_t len)
{
	cbl_dtree *t, *ft = NULL;
	char why[160];
	bool any;

	if ((t = cbl_dtree_new(sub->y.srv->schema)) == NULL)
		return (false);
	if (cbl_dnode_decode(cbl_dtree_root(t), n, content, len, 0, why,
	    sizeof(why), NULL) == 0)
		ft = cbl_dtree_filter_xpath(t, sub->xpath, why, sizeof(why));
	any = ft != NULL && cbl_dnode_first(cbl_dtree_root(ft)) != NULL;
	cbl_dtree_free(ft);
	cbl_dtree_free(t);
	return (any);
}

void
cbl_ysub_event(cbl_ctx *ctx, const struct cbl_ynode *n,
    const uint8_t *content, size_t len)
{
	struct cbl_ysub *sub, **v = NULL;
	size_t nv = 0, cap = 0;

	/* Those of the stream, held: sent without the lock. */
	pthread_mutex_lock(&ctx->ysublock);
	TAILQ_FOREACH(sub, &ctx->ysubs, link) {
		if (sub->stream == NULL || sub->dead ||
		    sub->y.srv->schema != n->module->schema)
			continue;
		/* Its replay is being sent: held, sent after it. */
		if (sub->replaying) {
			if (sub->xpath == NULL || selects(sub, n, content, len))
				(void)rec_add(&sub->held, &sub->nheld,
				    &sub->capheld, n->sid, content, len, NULL);
			continue;
		}
		if (nv == cap) {
			struct cbl_ysub **w = reallocarray(v, cap + 8,
			    sizeof(*w));

			if (w == NULL)
				break;
			v = w;
			cap += 8;
		}
		sub->refs++;
		v[nv++] = sub;
	}
	pthread_mutex_unlock(&ctx->ysublock);
	for (size_t i = 0; i < nv; i++) {
		sub = v[i];
		/* What the filter leaves out is no record of it; what the
		 * subscriber may not read, not sent. */
		if ((sub->xpath == NULL || selects(sub, n, content, len)) &&
		    event_ok(sub, n->sid))
			(void)send_record(sub, n->sid, content, len);
		sub_rele(sub);
	}
	free(v);
}

/* sub, by id, ended: its stream closed with text. */
static int
sub_stop(cbl_ctx *ctx, const cbl_conn *conn, uint32_t id, const char *text)
{
	struct cbl_ysub *sub;

	pthread_mutex_lock(&ctx->ysublock);
	TAILQ_FOREACH(sub, &ctx->ysubs, link)
		if (sub->id == id && (conn == NULL ||
		    cbl_stream_conn(sub->s) == conn))
			break;
	if (sub == NULL) {
		pthread_mutex_unlock(&ctx->ysublock);
		return (ENOENT);
	}
	sub->refs++;
	sub_end(sub);
	pthread_mutex_unlock(&ctx->ysublock);
	(void)cbl_stream_close(sub->s, ECANCELED, text);
	sub_rele(sub);
	return (0);
}

int
cbl_ysub_delete(cbl_req *req, uint32_t id)
{

	if (req == NULL)
		return (EINVAL);
	return (sub_stop(req->conn->ctx, req->conn, id, "deleted"));
}

/* With ysublock held: the subscription of id on conn (NULL: any). */
static struct cbl_ysub *
sub_find(cbl_ctx *ctx, const cbl_conn *conn, uint32_t id)
{
	struct cbl_ysub *sub;

	TAILQ_FOREACH(sub, &ctx->ysubs, link)
		if (sub->id == id && !sub->dead && (conn == NULL ||
		    cbl_stream_conn(sub->s) == conn))
			return (sub);
	return (NULL);
}

static int
retire(struct cbl_ysub *sub, void *p)
{
	void **v;

	if (p == NULL)
		return (0);
	if ((v = reallocarray(sub->retired, sub->nretired + 1,
	    sizeof(*v))) == NULL)
		return (ENOMEM);
	sub->retired = v;
	v[sub->nretired++] = p;
	return (0);
}

/*
 * modify-subscription (RFC 8639 section 2.4.3, RFC 8641 section
 * 4.4.2): the filter, the stop-time, the period or the dampening period
 * of the requester's own subscription changed; the target stays.  The
 * subscriber is told subscription-modified.
 */
int
cbl_ysub_modify(cbl_req *req, const void *in)
{
	cbl_ctx *ctx;
	struct ynodes y;
	struct cbl_ysub *sub, want;
	const struct cbl_ynode *sn;
	const cbl_dnode *c, *pc;
	cbl_dtree *t = NULL, *ft = NULL;
	cbl_dnode *dr, *din;
	const void *v;
	uint32_t id = 0;
	char why[160];
	int error = 0;

	if (req == NULL || in == NULL)
		return (EINVAL);
	ctx = req->conn->ctx;
	if (!nodes(ctx, &y) || y.mod_in == NULL)
		return (cbl_ysay(req, EOPNOTSUPP, 0, "operation-not-supported",
		    "no modify-subscription in the tables"));
	memset(&want, 0, sizeof(want));
	want.y = y;
	want.ctx = ctx;
	if ((t = cbl_dtree_new(y.srv->schema)) == NULL)
		return (ENOMEM);
	if ((error = cbl_dnode_add(cbl_dtree_root(t), y.mod_in->parent !=
	    NULL ? y.mod_in->parent : y.rpc, NULL, &dr)) != 0 ||
	    (error = cbl_dnode_from_struct(dr, y.mod_in, in, &din)) != 0) {
		cbl_dtree_free(t);
		return (error);
	}
	for (c = cbl_dnode_first(din); error == 0 && c != NULL;
	    c = cbl_dnode_next(c)) {
		sn = cbl_dnode_schema(c);
		v = cbl_dnode_value(c);
		if (strcmp(sn->name, "id") == 0)
			id = *(const uint32_t *)v;
		else if (strcmp(sn->name, "stream-xpath-filter") == 0 ||
		    strcmp(sn->name, "datastore-xpath-filter") == 0)
			want.xpath = (char *)(uintptr_t)
			    *(const char *const *)v;
		else if (strcmp(sn->name, "stop-time") == 0) {
			want.stop_s = (char *)(uintptr_t)
			    *(const char *const *)v;
			if (!datetime(want.stop_s, &want.stop))
				error = cbl_ysay(req, EINVAL, sn->sid,
				    "invalid-value", "stop-time is no time");
			want.has_stop = true;
		} else if (strcmp(sn->name, "periodic") == 0 ||
		    strcmp(sn->name, "on-change") == 0) {
			for (pc = cbl_dnode_first(c); pc != NULL;
			    pc = cbl_dnode_next(pc)) {
				if (strcmp(cbl_dnode_schema(pc)->name,
				    "period") == 0)
					want.period = *(const uint32_t *)
					    cbl_dnode_value(pc);
				else if (strcmp(cbl_dnode_schema(pc)->name,
				    "dampening-period") == 0) {
					want.dampening = *(const uint32_t *)
					    cbl_dnode_value(pc);
					want.onchange = true;
				}
			}
			if (strcmp(sn->name, "on-change") == 0)
				want.onchange = true;
		} else if (strcmp(sn->name, "datastore") != 0) {
			char text[128];

			(void)snprintf(text, sizeof(text), "%s: not supported",
			    sn->name);
			error = cbl_ysay(req, EOPNOTSUPP, sn->sid,
			    "operation-not-supported", text);
		}
	}
	/* A new filter, tried on nothing first. */
	if (error == 0 && want.xpath != NULL) {
		cbl_dtree *e = cbl_dtree_new(y.srv->schema);

		if (e == NULL)
			error = ENOMEM;
		else if ((ft = cbl_dtree_filter_xpath(e, want.xpath, why,
		    sizeof(why))) == NULL)
			error = cbl_ysay(req, EINVAL, 0, "invalid-value", why);
		cbl_dtree_free(ft);
		cbl_dtree_free(e);
	}
	if (error == 0 && want.period != 0 && want.period < 10)
		error = cbl_ysay(req, EINVAL, 0, "invalid-value",
		    "the period is 10 centiseconds at least");
	if (error != 0) {
		cbl_dtree_free(t);
		return (error);
	}
	pthread_mutex_lock(&ctx->ysublock);
	if ((sub = sub_find(ctx, req->conn, id)) == NULL) {
		pthread_mutex_unlock(&ctx->ysublock);
		cbl_dtree_free(t);
		return (cbl_ysay(req, ENOENT, 0, "invalid-value",
		    "no such subscription of this connection"));
	}
	if (want.onchange != sub->onchange || (want.period != 0 &&
	    sub->stream != NULL)) {
		pthread_mutex_unlock(&ctx->ysublock);
		cbl_dtree_free(t);
		return (cbl_ysay(req, EINVAL, 0, "invalid-value",
		    "the kind of trigger is not changed"));
	}
	if (want.xpath != NULL) {
		char *x = strdup(want.xpath);

		if (x == NULL || retire(sub, sub->xpath) != 0)
			error = ENOMEM;
		else {
			sub->xpath = x;
			if (sub->stream == NULL) {
				(void)retire(sub, sub->top);
				sub->top = NULL;
				error = targets(sub);
			}
		}
	}
	if (error == 0 && want.has_stop) {
		char *x = strdup(want.stop_s);

		if (x == NULL || retire(sub, sub->stop_s) != 0)
			error = ENOMEM;
		else {
			sub->stop_s = x;
			sub->stop = want.stop;
			sub->has_stop = true;
		}
	}
	if (error == 0 && want.period != 0)
		sub->period = want.period;
	if (error == 0 && want.onchange && want.dampening != 0) {
		sub->dampening = want.dampening;
		sub->period = want.dampening > 100 ? want.dampening : 100;
	}
	if (error == 0 && (sub->period != 0 || sub->has_stop))
		error = sub_start(sub);
	sub->kick = true;
	pthread_cond_broadcast(&sub->cv);
	sub->refs++;
	pthread_mutex_unlock(&ctx->ysublock);
	cbl_dtree_free(t);
	if (error == 0)
		(void)send_state(sub, y.n_modified, 0);
	sub_rele(sub);
	return (error);
}

/* resync-subscription (RFC 8641 section 4.4.1): the whole of it again. */
int
cbl_ysub_resync(cbl_req *req, uint32_t id)
{
	cbl_ctx *ctx;
	struct cbl_ysub *sub;

	if (req == NULL)
		return (EINVAL);
	ctx = req->conn->ctx;
	pthread_mutex_lock(&ctx->ysublock);
	if ((sub = sub_find(ctx, req->conn, id)) == NULL || !sub->onchange) {
		pthread_mutex_unlock(&ctx->ysublock);
		return (cbl_ysay(req, ENOENT, 0, "invalid-value",
		    "no on-change subscription of that id on this connection"));
	}
	atomic_store(&sub->resync, true);
	sub->kick = true;
	pthread_cond_broadcast(&sub->cv);
	pthread_mutex_unlock(&ctx->ysublock);
	return (0);
}

int
cbl_ysub_told(cbl_ctx *ctx, const struct cbl_ynode *const *tops, size_t n)
{
	uint64_t *v = NULL;

	if (ctx == NULL || (n > 0 && tops == NULL))
		return (EINVAL);
	for (size_t i = 0; i < n; i++)
		if (tops[i] == NULL || !cbl_yis_top_data(tops[i]))
			return (EINVAL);
	if (n > 0 && (v = calloc(n, sizeof(*v))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < n; i++)
		v[i] = tops[i]->sid;
	pthread_mutex_lock(&ctx->ysublock);
	free(ctx->ytold);
	ctx->ytold = v;
	ctx->nytold = n;
	pthread_mutex_unlock(&ctx->ysublock);
	return (0);
}

void
cbl_ysub_changed(cbl_ctx *ctx, const struct cbl_ynode *top)
{
	struct cbl_ysub *sub;
	size_t i;

	if (ctx == NULL)
		return;
	pthread_mutex_lock(&ctx->ysublock);
	TAILQ_FOREACH(sub, &ctx->ysubs, link) {
		if (!sub->onchange || sub->dead || (top != NULL &&
		    sub->y.srv->schema != top->module->schema))
			continue;
		for (i = 0; top != NULL && i < sub->ntop; i++)
			if (sub->top[i] == top->sid)
				break;
		if (top != NULL && i == sub->ntop)
			continue;
		sub->dirty = true;
		pthread_cond_broadcast(&sub->cv);
	}
	pthread_mutex_unlock(&ctx->ysublock);
}

int
cbl_ysub_kill(cbl_ctx *ctx, uint32_t id)
{

	if (ctx == NULL)
		return (EINVAL);
	return (sub_stop(ctx, NULL, id, "killed"));
}

int
cbl_ysub_each(cbl_ctx *ctx, int (*fn)(const struct cbl_ysub_info *, void *),
    void *arg)
{
	struct cbl_ysub_info in;
	struct cbl_ysub *sub;
	int error = 0;

	if (ctx == NULL || fn == NULL)
		return (EINVAL);
	pthread_mutex_lock(&ctx->ysublock);
	TAILQ_FOREACH(sub, &ctx->ysubs, link) {
		memset(&in, 0, sizeof(in));
		in.id = sub->id;
		in.stream = sub->stream;
		in.datastore = sub->datastore;
		in.xpath = sub->xpath;
		in.period = sub->onchange ? 0 : sub->period;
		in.on_change = sub->onchange;
		in.dampening = sub->dampening;
		in.anchor_time = sub->anchor_s;
		in.stop_time = sub->stop_s;
		in.sent = atomic_load(&sub->sent);
		in.excluded = atomic_load(&sub->excluded);
		in.suspended = atomic_load(&sub->suspended);
		in.receiver = sub->receiver;
		if ((error = fn(&in, arg)) != 0)
			break;
	}
	pthread_mutex_unlock(&ctx->ysublock);
	return (error);
}
