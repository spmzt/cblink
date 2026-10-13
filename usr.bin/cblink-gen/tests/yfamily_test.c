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
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cbl_net_test.h"
#include "yangh.h"

static const struct cbl_ynode *n_shapes, *n_system, *n_state, *n_ping;
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

/* /system-state: state, read only. */
static int
state_get(cbl_req *req, void *data, cbl_yarena *a)
{
	struct ietf_system_system_state *st;
	struct ietf_system_system_state_platform *pl;

	(void)req;
	if ((st = cbl_yarena_alloc(a, sizeof(*st))) == NULL ||
	    (pl = cbl_yarena_alloc(a, sizeof(*pl))) == NULL)
		return (ENOMEM);
	pl->os_name = "FreeBSD";
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

static struct cbl_yhandler handlers[4];
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
	ATF_REQUIRE_STREQ("the edit failed", cbl_msg_err_str(r));
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

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, get_edit);
	ATF_TP_ADD_TC(tp, edit_rollback);
	ATF_TP_ADD_TC(tp, refusals);
	ATF_TP_ADD_TC(tp, rpc);
	ATF_TP_ADD_TC(tp, dump);
	return (atf_no_error());
}
