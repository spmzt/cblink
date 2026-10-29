/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Family 1, "cblink.yang", over a connection: a server of the shapes and
 * ietf-system tables cblink-gen made for yang_h_test, its handlers these,
 * and a client that reads, edits and calls through GET, EDIT and RPC.
 */

#include <atf-c.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cbl_net_test.h"
#include "yangh.h"

static const struct cbl_ynode *n_shapes, *n_system, *n_state, *n_ping;
static const struct cbl_ynode *n_item, *n_reset;
static int marker;		/* the handlers' arg */

/* shapes, kept as YANG-CBOR: what the last edit left. */
static struct cbl_ybuf store;
static bool have;

static const struct cbl_ynode *
top(const char *mod, const char *name)
{

	for (uint32_t i = 0; i < yangh_schema.nmod; i++) {
		const struct cbl_ymodule *m = yangh_schema.mod[i];

		if (strcmp(m->name, mod) != 0)
			continue;
		for (uint32_t j = 0; j < m->ntop; j++)
			if (strcmp(m->top[j]->name, name) == 0)
				return (m->top[j]);
	}
	atf_tc_fail("no %s:%s", mod, name);
}

static int
shapes_get(cbl_req *req, void *data, cbl_yarena *a)
{

	ATF_CHECK(cbl_req_yarg(req) == &marker);
	if (!have)
		return (0);
	return (cbl_ydecode_member(n_shapes, store.p, store.len, data, a,
	    CBL_YD_STRICT, NULL, 0));
}

static int
shapes_edit(cbl_req *req, const void *before, const void *after)
{

	(void)before;
	ATF_CHECK(cbl_req_yarg(req) == &marker);
	cbl_ybuf_free(&store);
	memset(&store, 0, sizeof(store));
	have = false;
	if (((const struct shapes *)after)->shapes == NULL)
		return (0);
	if (cbl_yencode_member(n_shapes, after, &store) != 0)
		return (EIO);
	have = true;
	return (0);
}

/* /system: an edit with contact "fail" fails. */
static int
system_edit(cbl_req *req, const void *before, const void *after)
{
	const struct ietf_system *s = after;

	(void)req;
	(void)before;
	if (s->system != NULL && s->system->contact != NULL &&
	    strcmp(s->system->contact, "fail") == 0)
		return (EIO);
	return (0);
}

/* A slow read (the threads case), and buffers freed with the arena. */
static atomic_bool slow;
static atomic_int freed;

static void
free_name(void *p)
{

	free(p);
	atomic_fetch_add(&freed, 1);
}

/* /system-state: state, read only; its name a buffer of its own, freed
 * when the answer's arena is (cbl_yarena_atfree()). */
static int
state_get(cbl_req *req, void *data, cbl_yarena *a)
{
	struct ietf_system_system_state *st;
	struct ietf_system_system_state_platform *pl;
	char *name;

	(void)req;
	if (atomic_load(&slow))
		usleep(800000);
	if ((st = cbl_yarena_alloc(a, sizeof(*st))) == NULL ||
	    (pl = cbl_yarena_alloc(a, sizeof(*pl))) == NULL ||
	    (name = strdup("FreeBSD")) == NULL)
		return (ENOMEM);
	if (cbl_yarena_atfree(a, free_name, name) != 0) {
		free(name);
		return (ENOMEM);
	}
	pl->os_name = name;
	st->platform = pl;
	((struct ietf_system *)data)->system_state = st;
	return (0);
}

/* ping: a count over 10 is refused, the error at the rpc. */
static int
ping_rpc(cbl_req *req, const void *in, void *out, cbl_yarena *a)
{
	const struct shapes_ping_input *p = in;

	(void)out;
	(void)a;
	if (p->has_count && p->count > 10) {
		(void)cbl_req_set_yerr(req, "too many", n_ping->sid);
		return (ERANGE);
	}
	return (0);
}

/* reset, an action of an item: what it was given, the target kept. */
static uint8_t reset_target[64];
static size_t reset_len;

static int
reset_action(cbl_req *req, const struct cbl_bytes *target, const void *in,
    void *out, cbl_yarena *a)
{
	const struct shapes_shapes_item_reset_input *i = in;
	struct shapes_shapes_item_reset_output *o = out;
	const struct cbl_ynode *n;
	const void **vals;
	size_t nvals;

	(void)req;
	if (target->len > sizeof(reset_target))
		return (EINVAL);
	memcpy(reset_target, target->p, target->len);
	reset_len = target->len;
	/* Its item's id, the key, as a handler reads it; hard: doubled. */
	if (cbl_yiid_read(&yangh_schema, target, &n, &vals, &nvals, a) != 0 ||
	    n != n_item || nvals != 1)
		return (EINVAL);
	o->has_took = true;
	o->took = *(const uint32_t *)vals[0] * (i->has_hard && i->hard ? 2 : 1);
	return (0);
}

static const struct cbl_ynode *
child(const struct cbl_ynode *n, const char *name)
{

	for (uint32_t i = 0; i < n->nchild; i++)
		if (strcmp(n->child[i]->name, name) == 0)
			return (n->child[i]);
	atf_tc_fail("no %s under %s", name, n->name);
}

static struct cbl_yhandler handlers[5];
static struct cbl_yserver server = { .schema = &yangh_schema };

static int
hcmp(const void *a, const void *b)
{
	const struct cbl_yhandler *x = a, *y = b;

	return ((x->sid > y->sid) - (x->sid < y->sid));
}

struct fixture {
	cbl_ctx			*sctx;
	cbl_ctx			*cctx;
	struct test_server	 ts;
	cbl_conn		*c;
};

static void
setup(struct fixture *f)
{

	n_shapes = top("shapes", "shapes");
	n_ping = top("shapes", "ping");
	n_system = top("ietf-system", "system");
	n_state = top("ietf-system", "system-state");
	handlers[0] = (struct cbl_yhandler){ n_shapes->sid, shapes_get,
	    shapes_edit, NULL, NULL };
	handlers[1] = (struct cbl_yhandler){ n_ping->sid, NULL, NULL,
	    ping_rpc, NULL };
	handlers[2] = (struct cbl_yhandler){ n_system->sid, NULL,
	    system_edit, NULL, NULL };
	handlers[3] = (struct cbl_yhandler){ n_state->sid, state_get, NULL,
	    NULL, NULL };
	n_item = child(n_shapes, "item");
	n_reset = child(n_item, "reset");
	handlers[4] = (struct cbl_yhandler){ n_reset->sid, NULL, NULL, NULL,
	    reset_action };
	qsort(handlers, nitems(handlers), sizeof(handlers[0]), hcmp);
	server.nhandler = nitems(handlers);
	server.handler = handlers;
	have = false;

	f->sctx = test_ctx();
	f->cctx = test_ctx();
	ATF_REQUIRE_EQ(0, cbl_yserver_add(f->sctx, &server, &marker));
	ATF_REQUIRE_EQ(EEXIST, cbl_yserver_add(f->sctx, &server, &marker));
	test_server_start(&f->ts, f->sctx, "tcp://127.0.0.1:0",
	    CBL_PLAINTEXT);
	ATF_REQUIRE_EQ(0, cbl_conn_new(f->cctx, f->ts.uri, CBL_PLAINTEXT,
	    &f->c));
	ATF_REQUIRE_EQ(0, cbl_conn_connect(f->c));
}

static void
teardown(struct fixture *f)
{

	cbl_conn_free(f->c);
	test_server_stop(&f->ts);
	cbl_ctx_free(f->sctx);
	cbl_ctx_free(f->cctx);
	cbl_ybuf_free(&store);
	memset(&store, 0, sizeof(store));
}

static cbl_msg *
new_req(struct fixture *f, uint16_t cmd)
{
	cbl_msg *m;

	ATF_REQUIRE_EQ(0, cbl_msg_new(f->cctx, CBL_YANG_FAMILY, cmd, 0, &m));
	return (m);
}

/* EDIT shapes' ratio to v (0: shapes deleted), system's contact (NULL: none). */
static int
edit(struct fixture *f, int64_t v, const char *contact, cbl_msg **rp)
{
	struct shapes_shapes sh = { .has_ratio = true, .ratio = v };
	struct shapes d = { .shapes = &sh };
	struct ietf_system_system sys = { .contact = contact };
	struct ietf_system s = { .system = &sys };
	cbl_msg *m = new_req(f, CBL_YCMD_EDIT);

	if (v == 0)
		ATF_REQUIRE_EQ(0, cbl_msg_put_ynull(m, n_shapes->sid));
	else
		ATF_REQUIRE_EQ(0, cbl_msg_put_ymember(m, n_shapes, &d));
	if (contact != NULL)
		ATF_REQUIRE_EQ(0, cbl_msg_put_ymember(m, n_system, &s));
	return (cbl_request(f->c, m, rp, 5000));
}

/* GET shapes: its ratio, 0 when it is not there. */
static int64_t
get_ratio(struct fixture *f)
{
	struct shapes d = { 0 };
	cbl_msg *m = new_req(f, CBL_YCMD_GET), *r;
	cbl_yarena *a;
	int64_t v = 0;
	int error;

	ATF_REQUIRE_EQ(0, cbl_msg_put_yget(m, &n_shapes->sid, 1));
	ATF_REQUIRE_EQ(0, cbl_request(f->c, m, &r, 5000));
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	error = cbl_msg_ydecode_member(r, n_shapes, &d, a, CBL_YD_STRICT,
	    NULL, 0);
	if (error == 0) {
		ATF_REQUIRE(d.shapes != NULL && d.shapes->has_ratio);
		v = d.shapes->ratio;
	} else
		ATF_REQUIRE_EQ(ENOENT, error);
	cbl_yarena_free(a);
	cbl_msg_free(r);
	return (v);
}

ATF_TC_WITHOUT_HEAD(get_edit);
ATF_TC_BODY(get_edit, tc)
{
	struct ietf_system s = { 0 };
	struct fixture f;
	cbl_msg *m, *r;
	cbl_yarena *a;

	setup(&f);
	ATF_REQUIRE_EQ(0, get_ratio(&f));
	ATF_REQUIRE_EQ(0, edit(&f, 100, NULL, NULL));
	ATF_REQUIRE_EQ(100, get_ratio(&f));
	ATF_REQUIRE_EQ(0, edit(&f, 200, NULL, NULL));
	ATF_REQUIRE_EQ(200, get_ratio(&f));

	/* The whole datastore: shapes and system-state, what is there. */
	m = new_req(&f, CBL_YCMD_GET);
	ATF_REQUIRE_EQ(0, cbl_request(f.c, m, &r, 5000));
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	ATF_REQUIRE_EQ(0, cbl_msg_ydecode_member(r, n_state, &s, a,
	    CBL_YD_STRICT, NULL, 0));
	ATF_REQUIRE(s.system_state != NULL &&
	    s.system_state->platform != NULL);
	ATF_REQUIRE_STREQ("FreeBSD", s.system_state->platform->os_name);
	ATF_REQUIRE(cbl_msg_sid_raw(r, n_shapes->sid, &(const void *){ 0 },
	    &(size_t){ 0 }) == 0);
	/* system has no get handler: not read. */
	ATF_REQUIRE_EQ(ENOENT, cbl_msg_sid_raw(r, n_system->sid,
	    &(const void *){ 0 }, &(size_t){ 0 }));
	cbl_yarena_free(a);
	cbl_msg_free(r);

	/* null: deleted. */
	ATF_REQUIRE_EQ(0, edit(&f, 0, NULL, NULL));
	ATF_REQUIRE_EQ(0, get_ratio(&f));
	teardown(&f);
}

/* Two nodes edited, the second fails: the first is undone. */
ATF_TC_WITHOUT_HEAD(edit_rollback);
ATF_TC_BODY(edit_rollback, tc)
{
	struct fixture f;
	cbl_msg *r;

	setup(&f);
	ATF_REQUIRE_EQ(0, edit(&f, 100, "ok", NULL));
	ATF_REQUIRE_EQ(100, get_ratio(&f));
	ATF_REQUIRE_EQ(EIO, edit(&f, 300, "fail", &r));
	ATF_REQUIRE_EQ(n_system->sid, cbl_msg_err_sid(r));
	ATF_REQUIRE_STREQ("the edit failed: Input/output error",
	    cbl_msg_err_str(r));
	cbl_msg_free(r);
	ATF_REQUIRE_EQ(100, get_ratio(&f));
	teardown(&f);
}

ATF_TC_WITHOUT_HEAD(refusals);
ATF_TC_BODY(refusals, tc)
{
	struct ietf_system_system_state st = { 0 };
	struct ietf_system s = { .system_state = &st };
	uint64_t nosuch = UINT64_C(1099511627776) + 99999999;
	struct fixture f;
	cbl_msg *m, *r;

	setup(&f);
	/* A node no module has. */
	m = new_req(&f, CBL_YCMD_GET);
	ATF_REQUIRE_EQ(0, cbl_msg_put_yget(m, &nosuch, 1));
	ATF_REQUIRE_EQ(ENOENT, cbl_request(f.c, m, &r, 5000));
	ATF_REQUIRE_EQ(nosuch, cbl_msg_err_sid(r));
	cbl_msg_free(r);
	/* A node with no get handler. */
	m = new_req(&f, CBL_YCMD_GET);
	ATF_REQUIRE_EQ(0, cbl_msg_put_yget(m, &n_system->sid, 1));
	ATF_REQUIRE_EQ(EOPNOTSUPP, cbl_request(f.c, m, &r, 5000));
	ATF_REQUIRE_EQ(n_system->sid, cbl_msg_err_sid(r));
	cbl_msg_free(r);
	/* State is not edited. */
	m = new_req(&f, CBL_YCMD_EDIT);
	ATF_REQUIRE_EQ(0, cbl_msg_put_ymember(m, n_state, &s));
	ATF_REQUIRE_EQ(EOPNOTSUPP, cbl_request(f.c, m, &r, 5000));
	ATF_REQUIRE_EQ(n_state->sid, cbl_msg_err_sid(r));
	cbl_msg_free(r);
	/*
	 * What the static validator refuses, the codec taking it: tuned,
	 * a presence container, without its mandatory max.
	 */
	{
		struct shapes_shapes_tuned t = { 0 };
		struct shapes_shapes bad = { .tuned = &t };
		struct shapes db = { .shapes = &bad };
		const struct cbl_ynode *tn = NULL, *mx = NULL;

		for (uint32_t i = 0; i < n_shapes->nchild; i++)
			if (strcmp(n_shapes->child[i]->name, "tuned") == 0)
				tn = n_shapes->child[i];
		ATF_REQUIRE(tn != NULL && tn->nchild == 1);
		mx = tn->child[0];
		m = new_req(&f, CBL_YCMD_EDIT);
		ATF_REQUIRE_EQ(0, cbl_msg_put_ymember(m, n_shapes, &db));
		ATF_REQUIRE_EQ(EINVAL, cbl_request(f.c, m, &r, 5000));
		ATF_REQUIRE_EQ_MSG(mx->sid, cbl_msg_err_sid(r), "%s",
		    cbl_msg_err_str(r));
		cbl_msg_free(r);
	}
	/* A value that is not the node's: nothing changed. */
	m = new_req(&f, CBL_YCMD_EDIT);
	ATF_REQUIRE_EQ(0, cbl_msg_put_sid_raw(m, n_shapes->sid, "\x01", 1));
	ATF_REQUIRE_EQ(EINVAL, cbl_request(f.c, m, &r, 5000));
	ATF_REQUIRE_EQ(n_shapes->sid, cbl_msg_err_sid(r));
	cbl_msg_free(r);
	ATF_REQUIRE_EQ(0, get_ratio(&f));
	teardown(&f);
}

ATF_TC_WITHOUT_HEAD(rpc);
ATF_TC_BODY(rpc, tc)
{
	struct shapes_ping_input in = { .has_count = true, .count = 3 };
	struct shapes_ping_output out;
	const struct cbl_ynode *n_in = NULL, *n_out = NULL;
	struct fixture f;
	const void *v;
	cbl_msg *m, *r;
	cbl_yarena *a;
	size_t len;

	setup(&f);
	for (uint32_t i = 0; i < n_ping->nchild; i++) {
		if (n_ping->child[i]->kind == CBL_YN_INPUT)
			n_in = n_ping->child[i];
		if (n_ping->child[i]->kind == CBL_YN_OUTPUT)
			n_out = n_ping->child[i];
	}
	ATF_REQUIRE(n_in != NULL && n_out != NULL);
	m = new_req(&f, CBL_YCMD_RPC);
	ATF_REQUIRE_EQ(0, cbl_msg_put_ynode(m, n_in, &in));
	ATF_REQUIRE_EQ(0, cbl_request(f.c, m, &r, 5000));
	/* No output: {ping: null}, read as an empty one. */
	ATF_REQUIRE_EQ(0, cbl_msg_sid_raw(r, n_ping->sid, &v, &len));
	ATF_REQUIRE(len == 1 && *(const uint8_t *)v == 0xf6);
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	ATF_REQUIRE_EQ(0, cbl_msg_ydecode(r, n_out, &out, a, CBL_YD_STRICT,
	    NULL, 0));
	cbl_yarena_free(a);
	cbl_msg_free(r);

	/* The handler's refusal, at the rpc. */
	in.count = 20;
	m = new_req(&f, CBL_YCMD_RPC);
	ATF_REQUIRE_EQ(0, cbl_msg_put_ynode(m, n_in, &in));
	ATF_REQUIRE_EQ(ERANGE, cbl_request(f.c, m, &r, 5000));
	ATF_REQUIRE_EQ(n_ping->sid, cbl_msg_err_sid(r));
	ATF_REQUIRE_STREQ("too many", cbl_msg_err_str(r));
	cbl_msg_free(r);

	/* Not an rpc; two in one request. */
	m = new_req(&f, CBL_YCMD_RPC);
	ATF_REQUIRE_EQ(0, cbl_msg_put_ynull(m, n_shapes->sid));
	ATF_REQUIRE_EQ(ENOENT, cbl_request(f.c, m, &r, 5000));
	cbl_msg_free(r);
	m = new_req(&f, CBL_YCMD_RPC);
	ATF_REQUIRE_EQ(0, cbl_msg_put_ynull(m, n_ping->sid));
	ATF_REQUIRE_EQ(0, cbl_msg_put_ynull(m, n_shapes->sid));
	ATF_REQUIRE_EQ(EINVAL, cbl_request(f.c, m, &r, 5000));
	cbl_msg_free(r);
	/* null: an empty input. */
	m = new_req(&f, CBL_YCMD_RPC);
	ATF_REQUIRE_EQ(0, cbl_msg_put_ynull(m, n_ping->sid));
	ATF_REQUIRE_EQ(0, cbl_request(f.c, m, NULL, 5000));
	teardown(&f);
}

struct dumped {
	atomic_int	 frames;
	atomic_int	 done;
	atomic_int	 error;
	atomic_bool	 one_each;	/* each frame one node */
};

static void
dump_cb(cbl_conn *conn, cbl_msg *m, bool final, int error, void *arg)
{
	struct dumped *d = arg;
	const void *v;
	size_t len;

	(void)conn;
	if (final) {
		d->error = error;
		d->done = 1;
		return;
	}
	if ((cbl_msg_sid_raw(m, n_shapes->sid, &v, &len) == 0) +
	    (cbl_msg_sid_raw(m, n_state->sid, &v, &len) == 0) != 1)
		d->one_each = false;
	d->frames++;
}

ATF_TC_WITHOUT_HEAD(dump);
ATF_TC_BODY(dump, tc)
{
	struct dumped d = { .one_each = true };
	struct timespec t0, t1;
	struct pollfd pfd;
	struct fixture f;
	int events, timeout;
	cbl_msg *m;

	setup(&f);
	ATF_REQUIRE_EQ(0, edit(&f, 100, NULL, NULL));
	ATF_REQUIRE_EQ(0, cbl_msg_new(f.cctx, CBL_YANG_FAMILY, CBL_YCMD_GET,
	    CBL_F_DUMP, &m));
	ATF_REQUIRE_EQ(0, cbl_request_async(f.c, m, dump_cb, &d));
	clock_gettime(CLOCK_MONOTONIC, &t0);
	while (d.done == 0) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		ATF_REQUIRE(t1.tv_sec - t0.tv_sec < 5);
		cbl_conn_interest(f.c, &events, &timeout);
		pfd.fd = cbl_conn_fd(f.c);
		pfd.events = POLLIN | ((events & CBL_EV_WRITE) ? POLLOUT : 0);
		(void)poll(&pfd, 1, 10);
		(void)cbl_conn_process(f.c,
		    ((pfd.revents & POLLIN) ? CBL_EV_READ : 0) |
		    ((pfd.revents & POLLOUT) ? CBL_EV_WRITE : 0));
	}
	ATF_REQUIRE_EQ(0, d.error);
	/* shapes and system-state, a frame each; system is not read. */
	ATF_REQUIRE_EQ(2, d.frames);
	ATF_REQUIRE(d.one_each);
	teardown(&f);
}

struct heard {
	atomic_int	 n;
	uint64_t	 sid;
	char		 text[32];
	char		 time[40];
};

static void
heard_cb(cbl_conn *conn, cbl_msg *m, void *arg)
{
	struct heard *h = arg;
	struct shapes_alarm al = { 0 };
	struct cbl_ynotif nt;
	cbl_yarena *a;

	(void)conn;
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	ATF_REQUIRE_EQ(CBL_YCMD_NOTIFY, cbl_msg_cmd(m));
	ATF_REQUIRE_EQ(0, cbl_msg_ynotif(m, &nt, a));
	h->sid = nt.sid;
	strlcpy(h->time, nt.event_time, sizeof(h->time));
	ATF_REQUIRE_EQ(0, cbl_ydecode(top("shapes", "alarm"), nt.content,
	    nt.len, &al, a, CBL_YD_STRICT, NULL, 0));
	strlcpy(h->text, al.text != NULL ? al.text : "", sizeof(h->text));
	cbl_yarena_free(a);
	h->n++;
}

/* A notification, to the subscribers of group "notify". */
ATF_TC_WITHOUT_HEAD(notify);
ATF_TC_BODY(notify, tc)
{
	const struct cbl_ynode *alarm = top("shapes", "alarm");
	struct shapes_alarm al = { .text = "hot" };
	struct heard h = { 0 };
	struct timespec t0, t1;
	struct pollfd pfd;
	struct fixture f;
	int events, timeout;
	cbl_sub *sub;

	setup(&f);
	ATF_REQUIRE_EQ(EINVAL, cbl_ynotify(f.sctx, n_shapes, &al));
	ATF_REQUIRE_EQ(0, cbl_subscribe(f.c, "cblink.yang", "notify",
	    heard_cb, &h, &sub));
	ATF_REQUIRE_EQ(0, cbl_ynotify(f.sctx, alarm, &al));
	clock_gettime(CLOCK_MONOTONIC, &t0);
	while (h.n == 0) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		ATF_REQUIRE(t1.tv_sec - t0.tv_sec < 5);
		cbl_conn_interest(f.c, &events, &timeout);
		pfd.fd = cbl_conn_fd(f.c);
		pfd.events = POLLIN | ((events & CBL_EV_WRITE) ? POLLOUT : 0);
		(void)poll(&pfd, 1, 10);
		(void)cbl_conn_process(f.c,
		    ((pfd.revents & POLLIN) ? CBL_EV_READ : 0) |
		    ((pfd.revents & POLLOUT) ? CBL_EV_WRITE : 0));
	}
	ATF_REQUIRE_EQ(alarm->sid, h.sid);
	ATF_REQUIRE_STREQ("hot", h.text);
	/* RFC 3339 in UTC: 2026-10-13T23:59:59.000000Z. */
	ATF_REQUIRE_EQ(27, strlen(h.time));
	ATF_REQUIRE(h.time[10] == 'T' && h.time[26] == 'Z');
	ATF_REQUIRE_EQ(0, cbl_unsubscribe(sub));
	teardown(&f);
}

/*
 * The event's key is a delta from its own SID, 60 000 + 47: a notification
 * of a smaller SID, a negative one.
 */
ATF_TC_WITHOUT_HEAD(notif_delta);
ATF_TC_BODY(notif_delta, tc)
{
	/* {+1 event-time: "t", +2 event: {-3: {}}} */
	static const uint8_t env[] = { 0xa2, 0x01, 0x61, 't', 0x02, 0xa1, 0x22,
	    0xa0 };
	cbl_ctx *ctx = test_ctx();
	struct cbl_ynotif nt;
	const void *fr;
	cbl_msg *m, *rx;
	cbl_yarena *a;
	size_t len;

	/* Not a NOTIFY frame, which needs a group: the body is what counts. */
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, CBL_YANG_FAMILY, CBL_YCMD_NOTIFY, 0,
	    &m));
	ATF_REQUIRE_EQ(0, cbl_msg_put_sid_raw(m, UINT64_C(60000) + 45,
	    env, sizeof(env)));
	ATF_REQUIRE_EQ(0, cbl_msg_encode(m, &fr, &len));
	ATF_REQUIRE_EQ(0, cbl_frame_decode(ctx, fr, len, NULL, &rx));
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	ATF_REQUIRE_EQ(0, cbl_msg_ynotif(rx, &nt, a));
	ATF_REQUIRE_EQ(UINT64_C(60000) + 44, nt.sid);
	ATF_REQUIRE_STREQ("t", nt.event_time);
	ATF_REQUIRE(nt.len == 1 && *(const uint8_t *)nt.content == 0xa0);
	cbl_yarena_free(a);
	cbl_msg_free(rx);
	cbl_msg_free(m);
	cbl_ctx_free(ctx);
}

/*
 * An action, item 7's reset: its target an item's instance-identifier,
 * [SID, 7], cbl_yiid_write()'s, the action given it as it was sent; its
 * output its own.  None, or one of another node, refused.
 */
ATF_TC_WITHOUT_HEAD(action);
ATF_TC_BODY(action, tc)
{
	struct shapes_shapes_item_reset_input in = { .has_hard = true,
	    .hard = true };
	struct shapes_shapes_item_reset_output out;
	const struct cbl_ynode *n_in, *n_out;
	struct cbl_ybuf t = { NULL, 0, 0 };
	uint32_t id = 0;
	const void *vals[] = { &id };
	struct fixture f;
	cbl_msg *m, *r;
	cbl_yarena *a;

	setup(&f);
	n_in = child(n_reset, "input");
	n_out = child(n_reset, "output");
	/* The key as a person gives it, read as its member is. */
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	ATF_REQUIRE_EQ(0, cbl_yvalue_parse(child(n_item, "id"),
	    child(n_item, "id")->type, "7", &id, a));
	ATF_REQUIRE_EQ(7, id);
	ATF_REQUIRE(cbl_yvalue_parse(child(n_item, "id"), child(n_item,
	    "id")->type, "seven", &id, a) != 0);
	id = 7;
	cbl_yarena_free(a);
	ATF_REQUIRE_EQ(0, cbl_yiid_write(n_item, vals, 1, &t));
	/* [SID, 7]: an array of two, the SID, then 7. */
	ATF_REQUIRE(t.len >= 3 && ((const uint8_t *)t.p)[0] == 0x82 &&
	    ((const uint8_t *)t.p)[t.len - 1] == 0x07);
	ATF_REQUIRE_EQ(EINVAL, cbl_yiid_write(n_item, vals, 0, &t));
	m = new_req(&f, CBL_YCMD_RPC);
	ATF_REQUIRE_EQ(0, cbl_msg_put_ynode(m, n_in, &in));
	ATF_REQUIRE_EQ(0, cbl_msg_put_yaction(m, t.p, t.len));
	ATF_REQUIRE_EQ(0, cbl_request(f.c, m, &r, 5000));
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	memset(&out, 0, sizeof(out));
	ATF_REQUIRE_EQ(0, cbl_msg_ydecode(r, n_out, &out, a, CBL_YD_STRICT,
	    NULL, 0));
	ATF_CHECK(out.has_took && out.took == 14);
	ATF_CHECK(reset_len == t.len && memcmp(reset_target, t.p, t.len) ==
	    0);
	cbl_yarena_free(a);
	cbl_msg_free(r);
	/* No target. */
	m = new_req(&f, CBL_YCMD_RPC);
	ATF_REQUIRE_EQ(0, cbl_msg_put_ynode(m, n_in, &in));
	ATF_REQUIRE_EQ(EINVAL, cbl_request(f.c, m, &r, 5000));
	ATF_CHECK(strstr(cbl_msg_err_str(r), "target") != NULL);
	cbl_msg_free(r);
	/* The target another node, shapes itself. */
	cbl_ybuf_free(&t);
	memset(&t, 0, sizeof(t));
	ATF_REQUIRE_EQ(0, cbl_yiid_write(n_shapes, NULL, 0, &t));
	m = new_req(&f, CBL_YCMD_RPC);
	ATF_REQUIRE_EQ(0, cbl_msg_put_ynode(m, n_in, &in));
	ATF_REQUIRE_EQ(0, cbl_msg_put_yaction(m, t.p, t.len));
	ATF_REQUIRE_EQ(EINVAL, cbl_request(f.c, m, &r, 5000));
	ATF_CHECK(strstr(cbl_msg_err_str(r), "no instance") != NULL);
	cbl_msg_free(r);
	cbl_ybuf_free(&t);
	teardown(&f);
}

/*
 * A GET with an xpath filter (cblink:get's xpath-filter): of the whole
 * datastore, what the expression selects alone; one that is no XPath
 * refused, invalid-value; a dump with one refused.
 */
ATF_TC_WITHOUT_HEAD(filter);
ATF_TC_BODY(filter, tc)
{
	struct ietf_system s = { 0 };
	struct fixture f;
	cbl_msg *m, *r;
	cbl_yarena *a;
	const void *v;
	size_t len;

	setup(&f);
	ATF_REQUIRE_EQ(0, edit(&f, 100, NULL, NULL));
	/* shapes alone. */
	m = new_req(&f, CBL_YCMD_GET);
	ATF_REQUIRE_EQ(0, cbl_msg_put_yget_xpath(m, NULL, 0, "/shapes:shapes"));
	ATF_REQUIRE_EQ(0, cbl_request(f.c, m, &r, 5000));
	ATF_CHECK_EQ(0, cbl_msg_sid_raw(r, n_shapes->sid, &v, &len));
	ATF_CHECK_EQ(ENOENT, cbl_msg_sid_raw(r, n_state->sid, &v, &len));
	cbl_msg_free(r);
	/* system-state's platform: the node above it with it. */
	m = new_req(&f, CBL_YCMD_GET);
	ATF_REQUIRE_EQ(0, cbl_msg_put_yget_xpath(m, NULL, 0,
	    "/ietf-system:system-state/ietf-system:platform"));
	ATF_REQUIRE_EQ(0, cbl_request(f.c, m, &r, 5000));
	ATF_CHECK_EQ(ENOENT, cbl_msg_sid_raw(r, n_shapes->sid, &v, &len));
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	ATF_REQUIRE_EQ(0, cbl_msg_ydecode_member(r, n_state, &s, a,
	    CBL_YD_STRICT, NULL, 0));
	ATF_REQUIRE(s.system_state != NULL &&
	    s.system_state->platform != NULL);
	ATF_CHECK_STREQ("FreeBSD", s.system_state->platform->os_name);
	cbl_yarena_free(a);
	cbl_msg_free(r);
	/* Not an expression. */
	m = new_req(&f, CBL_YCMD_GET);
	ATF_REQUIRE_EQ(0, cbl_msg_put_yget_xpath(m, NULL, 0, "/["));
	ATF_REQUIRE_EQ(EINVAL, cbl_request(f.c, m, &r, 5000));
	cbl_msg_free(r);
	teardown(&f);
}

/* GET of system-state's os-name on c, as asked: "FreeBSD", or NULL. */
struct slowget {
	cbl_ctx		*ctx;
	cbl_conn	*c;
	bool		 ok;
};

static void *
get_state(void *p)
{
	struct slowget *g = p;
	struct ietf_system s = { 0 };
	cbl_msg *m, *r;
	cbl_yarena *a;

	g->ok = false;
	if (cbl_msg_new(g->ctx, CBL_YANG_FAMILY, CBL_YCMD_GET, 0, &m) != 0 ||
	    cbl_msg_put_yget(m, &n_state->sid, 1) != 0 ||
	    cbl_request(g->c, m, &r, 5000) != 0)
		return (NULL);
	if ((a = cbl_yarena_new()) != NULL && cbl_msg_ydecode_member(r,
	    n_state, &s, a, CBL_YD_STRICT, NULL, 0) == 0 &&
	    s.system_state != NULL && s.system_state->platform != NULL &&
	    s.system_state->platform->os_name != NULL)
		g->ok = strcmp(s.system_state->platform->os_name,
		    "FreeBSD") == 0;
	cbl_yarena_free(a);
	cbl_msg_free(r);
	return (NULL);
}

/*
 * cbl_yserver_threads(): a slow GET on one connection holds no other
 * request, which is answered first; what a handler gave of its own is
 * there in the answer, and freed after.
 */
ATF_TC_WITHOUT_HEAD(threads);
ATF_TC_BODY(threads, tc)
{
	struct fixture f;
	struct slowget g;
	struct timespec t0, t1;
	pthread_t tid;
	int before;

	setup(&f);
	ATF_REQUIRE_EQ(0, cbl_yserver_threads(f.sctx, true));
	ATF_REQUIRE_EQ(0, edit(&f, 100, NULL, NULL));
	g.ctx = f.cctx;
	ATF_REQUIRE_EQ(0, cbl_conn_new(f.cctx, f.ts.uri, CBL_PLAINTEXT, &g.c));
	ATF_REQUIRE_EQ(0, cbl_conn_connect(g.c));
	before = atomic_load(&freed);
	atomic_store(&slow, true);
	ATF_REQUIRE_EQ(0, pthread_create(&tid, NULL, get_state, &g));
	usleep(200000);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	ATF_CHECK_EQ(100, get_ratio(&f));
	clock_gettime(CLOCK_MONOTONIC, &t1);
	ATF_CHECK_MSG((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec -
	    t0.tv_nsec) / 1000000 < 400, "the quick GET waited for the slow");
	ATF_REQUIRE_EQ(0, pthread_join(tid, NULL));
	atomic_store(&slow, false);
	ATF_CHECK(g.ok);
	ATF_CHECK_EQ(before + 1, atomic_load(&freed));
	cbl_conn_free(g.c);
	teardown(&f);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, get_edit);
	ATF_TP_ADD_TC(tp, edit_rollback);
	ATF_TP_ADD_TC(tp, refusals);
	ATF_TP_ADD_TC(tp, rpc);
	ATF_TP_ADD_TC(tp, dump);
	ATF_TP_ADD_TC(tp, notify);
	ATF_TP_ADD_TC(tp, notif_delta);
	ATF_TP_ADD_TC(tp, threads);
	ATF_TP_ADD_TC(tp, action);
	ATF_TP_ADD_TC(tp, filter);
	return (atf_no_error());
}
