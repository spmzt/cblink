/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Family 1's subscriptions: RFC 8639's dynamic subscriptions and RFC
 * 8641's periodic YANG-Push, each a push stream (SUBSCRIBE).
 *
 *	open	{SID(establish-subscription): input}, as an rpc's: the
 *		NETCONF stream (stream, stream-xpath-filter) or the
 *		operational datastore (datastore, datastore-xpath-filter,
 *		periodic {period, anchor-time}); stop-time.  What else
 *		the input has is refused, by name.
 *	accept	{SID(establish-subscription): output}, the id.
 *	data	a cblink:notification each, as group "notify" carries
 *		them: an event of the stream, or a push-update {id,
 *		datastore-contents, incomplete-update}.
 *
 * The nodes are found by name in the tables of the server that has
 * ietf-subscribed-notifications; a datastore's needs ietf-yang-push and
 * ietf-datastores there too.  A periodic subscription has a thread of
 * its own that reads, at each period from its anchor, the top-level
 * nodes the filter's paths begin with (all of them, where it cannot
 * tell) through their get handlers, on a request of the stream's
 * connection (so a handler sees the subscriber as the peer), and pushes
 * what the filter selects.  A stop-time is kept by the same thread.  A
 * record that does not fit in the stream's credit is left out and
 * counted; RFC 8639's suspension is not done.  A subscription ends by
 * its stream, closed when stop-time comes, on delete or kill; a
 * dynamic subscription's end is its transport's (RFC 8639 section
 * 2.4.2), so no state notification is sent.
 */

#include <ctype.h>
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

/* The nodes a server's tables have for subscriptions. */
struct ynodes {
	const struct cbl_yserver *srv;
	const struct cbl_ynode	*rpc, *in, *out, *out_id;
	/* ietf-yang-push's push-update, its members; NULL: none. */
	const struct cbl_ynode	*pu, *pu_id, *pu_dc, *pu_inc;
	uint64_t		 operational;
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
	char			*receiver;
	_Atomic uint64_t	 sent, excluded;
	/* ysublock's. */
	bool			 dead, listed;
	int			 refs;
	pthread_cond_t		 cv;
};

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
	for (uint32_t i = 0; i < s->nident; i++) {
		id = &s->ident[i];
		if (strcmp(id->name, "operational") == 0 &&
		    strcmp(id->module->name, "ietf-datastores") == 0)
			y->operational = id->sid;
	}
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
	pthread_cond_destroy(&sub->cv);
	free(sub->stream);
	free(sub->xpath);
	free(sub->anchor_s);
	free(sub->stop_s);
	free(sub->top);
	free(sub->receiver);
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

/* One record on the stream; one that does not fit is left out. */
static int
send_record(struct cbl_ysub *sub, uint64_t sid, const uint8_t *content,
    size_t len)
{
	cbl_msg *m;
	int error;

	if ((error = cbl_stream_msg_new(sub->s, &m)) != 0)
		return (error);
	if ((error = cbl_ynotif_put(m, sid, content, len)) != 0) {
		cbl_msg_free(m);
		return (error);
	}
	if ((error = cbl_stream_send(sub->s, m)) == EAGAIN) {
		cbl_msg_free(m);
		atomic_fetch_add(&sub->excluded, 1);
		return (0);
	}
	if (error == 0)
		atomic_fetch_add(&sub->sent, 1);
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

/*
 * A push-update of what the filter selects: {id, datastore-contents:
 * {delta: value}, incomplete-update where a read failed}.
 */
static int
push(struct cbl_ysub *sub)
{
	const struct ynodes *y = &sub->y;
	struct cbl_ybuf dc = { 0 }, c = { 0 }, v = { 0 };
	struct cbl_req r;
	cbl_dtree *t = NULL, *ft = NULL;
	cbl_dnode *root = NULL, *n;
	bool incomplete = false;
	size_t count = 0;
	char why[160];
	int error;

	memset(&r, 0, sizeof(r));
	r.conn = cbl_stream_conn(sub->s);
	atomic_init(&r.refs, 1);
	if (cbl_yread_tree(&r, sub->top, sub->ntop, &t, &incomplete) != 0)
		incomplete = true;
	free(r.err_msg);
	if (t != NULL && sub->xpath != NULL &&
	    (ft = cbl_dtree_filter_xpath(t, sub->xpath, why,
	    sizeof(why))) == NULL)
		incomplete = true;
	if (ft != NULL || t != NULL)
		root = cbl_dtree_root(ft != NULL ? ft : t);
	for (n = root != NULL ? cbl_dnode_first(root) : NULL; n != NULL;
	    n = cbl_dnode_next(n))
		count++;
	error = buf_head(&dc, 5, count);
	for (n = root != NULL ? cbl_dnode_first(root) : NULL; error == 0 &&
	    n != NULL; n = cbl_dnode_next(n)) {
		if ((error = cbl_dnode_encode(n, &v)) == 0 &&
		    (error = buf_int(&dc, (int64_t)(cbl_dnode_schema(n)->sid -
		    y->pu_dc->sid))) == 0)
			error = buf_put(&dc, v.p, v.len);
		cbl_ybuf_free(&v);
		memset(&v, 0, sizeof(v));
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
	cbl_dtree_free(ft);
	cbl_dtree_free(t);
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

/*
 * A periodic subscription's pushes, and its stop-time.  The first push
 * is at once without an anchor-time, else at the anchor's first period
 * from now; each next one a period on from the anchor, past the push.
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
		if (sub->has_stop && !ts_before(&now, &sub->stop)) {
			stop = true;
			break;
		}
		if (sub->period != 0 && !ts_before(&now, &due)) {
			pthread_mutex_unlock(&sub->ctx->ysublock);
			error = push(sub);
			pthread_mutex_lock(&sub->ctx->ysublock);
			if (error == EPIPE)
				break;
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

static const struct cbl_stream_cbs sub_cbs = {
	.on_close = sub_closed,
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
	if (sub->has_stop && !ts_before(&now, &sub->stop))
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

/* The accept: the output, the id. */
static int
sub_accept_msg(cbl_req *req, const struct cbl_ysub *sub, cbl_msg **accp)
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
	struct cbl_ysub *sub;
	cbl_dtree *t = NULL;
	cbl_dnode *dr, *din;
	cbl_msg *acc = NULL;
	cbl_yarena *a;
	pthread_t tid;
	void *pin;
	char why[160];
	int error;

	if ((sub = calloc(1, sizeof(*sub))) == NULL)
		return (ENOMEM);
	sub->ctx = ctx;
	sub->refs = 1;
	pthread_cond_init(&sub->cv, NULL);
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
	if ((error = sub_accept_msg(req, sub, &acc)) != 0) {
		sub_rele(sub);
		return (error);
	}
	cbl_stream_ref(s);
	sub->s = s;
	/* Not accepted: no callback will run, sub still ours. */
	if ((error = cbl_stream_accept(s, acc, 0, &sub_cbs, sub)) != 0) {
		sub_rele(sub);
		return (error);
	}
	pthread_mutex_lock(&ctx->ysublock);
	TAILQ_INSERT_TAIL(&ctx->ysubs, sub, link);
	sub->listed = true;
	/* A thread for the periods and the stop-time. */
	if (sub->period != 0 || sub->has_stop) {
		sub->refs++;
		if (pthread_create(&tid, NULL, sub_thread, sub) != 0) {
			sub->refs--;
			sub_end(sub);
			pthread_mutex_unlock(&ctx->ysublock);
			(void)cbl_stream_close(s, ENOMEM, "no thread for it");
			return (0);
		}
		(void)pthread_detach(tid);
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
		/* What the filter leaves out is no record of it. */
		if (sub->xpath == NULL || selects(sub, n, content, len))
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
		in.period = sub->period;
		in.anchor_time = sub->anchor_s;
		in.stop_time = sub->stop_s;
		in.sent = atomic_load(&sub->sent);
		in.excluded = atomic_load(&sub->excluded);
		in.receiver = sub->receiver;
		if ((error = fn(&in, arg)) != 0)
			break;
	}
	pthread_mutex_unlock(&ctx->ysublock);
	return (error);
}
