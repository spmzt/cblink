/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* Families, dispatch, the control family, dumps and deferred replies. */

#include <stdatomic.h>
#include <time.h>

#include "cbl_net_test.h"

enum { T_ECHO = 1, T_FAIL, T_DEFER, T_LIST, T_SECRET, T_DUMPONLY, T_DEFERFAST,
    T_BIG, T_FOREVER };
enum { TA_VAL = 1, TA_N, TA_DELAY, TA_IDX };

static const struct cbl_policy echo_pol[] = {
	{ .type = TA_VAL, .kind = CBL_K_TEXT,
	  .flags = CBL_PF_REQUIRED | CBL_PF_RANGE, .len = { 1, 16 } },
};
CBL_POLICY_SET(echo_set, echo_pol);

static const struct cbl_policy list_pol[] = {
	{ .type = TA_N, .kind = CBL_K_UINT, .flags = CBL_PF_RANGE,
	  .u = { 0, 1000000 } },
};
CBL_POLICY_SET(list_set, list_pol);

static int
echo_doit(cbl_req *req, const cbl_msg *msg, void *arg __unused)
{
	cbl_msg *rsp;
	int error;

	if ((error = cbl_req_reply_new(req, 0, &rsp)) != 0)
		return (error);
	cbl_put_attr(rsp, TA_VAL, cbl_msg_attr(msg, TA_VAL));
	return (cbl_req_send(req, rsp));
}

static int
fail_doit(cbl_req *req, const cbl_msg *msg __unused, void *arg __unused)
{
	struct cbl_path_elem p[] = { { .v = TA_VAL } };

	cbl_req_set_err(req, "handler says no", p, 1, -1);
	cbl_req_set_cookie(req, "xyz", 3);
	return (EPERM);
}

/* Deferred: completed later from another thread, out of order. */
struct deferred {
	cbl_req		*req;
	uint64_t	 delay_ms;
	uint64_t	 idx;
};

static void *
defer_thread(void *arg)
{
	struct deferred *d = arg;
	cbl_msg *rsp;

	usleep((useconds_t)d->delay_ms * 1000);
	if (cbl_req_reply_new(d->req, 0, &rsp) == 0) {
		cbl_put_uint(rsp, TA_IDX, d->idx);
		(void)cbl_req_send(d->req, rsp);
	}
	(void)cbl_req_complete(d->req, 0);
	free(d);
	return (NULL);
}

static int
defer_doit(cbl_req *req, const cbl_msg *msg, void *arg __unused)
{
	struct deferred *d;
	pthread_t thr;

	if ((d = calloc(1, sizeof(*d))) == NULL)
		return (ENOMEM);
	d->req = req;
	(void)cbl_attr_uint(cbl_msg_attr(msg, TA_DELAY), &d->delay_ms);
	(void)cbl_attr_uint(cbl_msg_attr(msg, TA_IDX), &d->idx);
	ATF_REQUIRE_EQ(0, cbl_req_defer(req));
	ATF_REQUIRE_EQ(0, pthread_create(&thr, NULL, defer_thread, d));
	pthread_detach(thr);
	return (0);
}

/*
 * Deferred, and completed by another thread before the handler has even
 * returned: dispatch must not look at the request after the handler.
 */
static void *
complete_thread(void *arg)
{

	(void)cbl_req_complete(arg, 0);
	return (NULL);
}

static int
deferfast_doit(cbl_req *req, const cbl_msg *msg __unused, void *arg __unused)
{
	pthread_t thr;

	ATF_REQUIRE_EQ(0, cbl_req_defer(req));
	ATF_REQUIRE_EQ(0, pthread_create(&thr, NULL, complete_thread, req));
	pthread_join(thr, NULL);
	return (0);
}

/* A 1 KB reply: more than the kernel buffers when nobody reads. */
static int
big_doit(cbl_req *req, const cbl_msg *msg __unused, void *arg __unused)
{
	static const char pad[1024];
	cbl_msg *rsp;
	int error;

	if ((error = cbl_req_reply_new(req, 0, &rsp)) != 0)
		return (error);
	cbl_put_bytes(rsp, TA_VAL, pad, sizeof(pad));
	return (cbl_req_send(req, rsp));
}

/* Deferred and never completed by the handler: told when the peer leaves. */
static struct {
	atomic_int	 cancelled;
	cbl_req		*req;
} forever;

static void
forever_cancel(cbl_req *req, void *arg __unused)
{

	forever.req = req;
	forever.cancelled++;
}

static int
forever_doit(cbl_req *req, const cbl_msg *msg __unused, void *arg __unused)
{

	ATF_REQUIRE_EQ(0, cbl_req_defer(req));
	ATF_REQUIRE_EQ(0, cbl_req_set_cancel(req, forever_cancel, NULL));
	return (0);
}

/* Dump N items, one per call. */
static int
list_dumpit(cbl_req *req, const cbl_msg *msg, struct cbl_dump_state *st,
    void *arg __unused)
{
	uint64_t n = 10;
	cbl_msg *item;
	int error;

	uint64_t fail_at = UINT64_MAX;

	(void)cbl_attr_uint(cbl_msg_attr(msg, TA_N), &n);
	(void)cbl_attr_uint(cbl_msg_attr(msg, TA_DELAY), &fail_at);
	if (st->pos[0] >= n)
		return (0);
	if (st->pos[0] == fail_at) {
		cbl_req_set_err(req, "dump failed part-way", NULL, 0, -1);
		return (EIO);
	}
	if ((error = cbl_req_dump_item(req, &item)) != 0)
		return (error);
	cbl_put_uint(item, TA_IDX, st->pos[0]);
	cbl_put_bytes(item, TA_VAL, "0123456789abcdef0123456789abcdef", 32);
	if ((error = cbl_req_send(req, item)) != 0)
		return (error);
	st->pos[0]++;
	return (EAGAIN);
}

static const struct cbl_op test_ops[] = {
	{ .cmd = T_ECHO, .name = "echo", .flags = CBL_OPF_DO,
	  .policy = &echo_set, .doit = echo_doit },
	{ .cmd = T_FAIL, .name = "fail", .flags = CBL_OPF_DO,
	  .doit = fail_doit },
	{ .cmd = T_DEFER, .name = "defer", .flags = CBL_OPF_DO,
	  .doit = defer_doit },
	{ .cmd = T_LIST, .name = "list", .flags = CBL_OPF_DO | CBL_OPF_DUMP,
	  .policy = &list_set, .doit = echo_doit, .dumpit = list_dumpit },
	{ .cmd = T_SECRET, .name = "secret",
	  .flags = CBL_OPF_DO | CBL_OPF_AUTH, .doit = echo_doit },
	{ .cmd = T_DUMPONLY, .name = "dumponly", .flags = CBL_OPF_DUMP,
	  .dumpit = list_dumpit },
	{ .cmd = T_DEFERFAST, .name = "deferfast", .flags = CBL_OPF_DO,
	  .doit = deferfast_doit },
	{ .cmd = T_BIG, .name = "big", .flags = CBL_OPF_DO,
	  .doit = big_doit },
	{ .cmd = T_FOREVER, .name = "forever", .flags = CBL_OPF_DO,
	  .doit = forever_doit },
};

static const struct cbl_mcgrp test_grps[] = {
	{ .name = "events" },
	{ .name = "audit", .flags = CBL_MCF_AUTH },
};

static const struct cbl_family_def test_def = {
	.abi = CBL_FAMILY_ABI,
	.name = "test",
	.version = 3,
	.ops = test_ops,
	.nops = nitems(test_ops),
	.mcgrps = test_grps,
	.nmcgrps = nitems(test_grps),
};

ATF_TC_WITHOUT_HEAD(registry);
ATF_TC_BODY(registry, tc)
{
	cbl_ctx *ctx = test_ctx();
	struct cbl_family_def def = test_def;
	struct cbl_op badops[2];
	cbl_family *f1, *f2;

	ATF_REQUIRE_EQ(0, cbl_family_register(ctx, &test_def, NULL, &f1));
	ATF_REQUIRE(cbl_family_id(f1) >= 1);
	ATF_REQUIRE_EQ(2, cbl_family_group_id(f1, 0));
	ATF_REQUIRE_EQ(3, cbl_family_group_id(f1, 1));
	ATF_REQUIRE_EQ(0, cbl_family_group_id(f1, 2));
	ATF_REQUIRE_EQ(EEXIST, cbl_family_register(ctx, &test_def, NULL,
	    &f2));

	def.name = "other";
	ATF_REQUIRE_EQ(0, cbl_family_register(ctx, &def, NULL, &f2));
	ATF_REQUIRE(cbl_family_id(f2) != cbl_family_id(f1));
	ATF_REQUIRE_EQ(4, cbl_family_group_id(f2, 0));
	ATF_REQUIRE_EQ(0, cbl_family_unregister(f2));

	static const char *bad_names[] = { "", "Upper", "1abc", "ctrl",
	    "cblink.x", "a b",
	    "a234567890123456789012345678901234567890123456789012345678901234"
	};
	for (size_t i = 0; i < nitems(bad_names); i++) {
		def.name = bad_names[i];
		ATF_CHECK_EQ_MSG(EINVAL, cbl_family_register(ctx, &def, NULL,
		    &f2), "%s", bad_names[i]);
	}
	def.name = "bad";
	def.version = 0;
	ATF_REQUIRE_EQ(EINVAL, cbl_family_register(ctx, &def, NULL, &f2));
	def.version = 1;
	/* Unsorted ops; flags that do not match the handlers. */
	badops[0] = test_ops[1];
	badops[1] = test_ops[0];
	def.ops = badops;
	def.nops = 2;
	ATF_REQUIRE_EQ(EINVAL, cbl_family_register(ctx, &def, NULL, &f2));
	badops[0] = test_ops[0];
	badops[0].flags |= CBL_OPF_DUMP;
	def.nops = 1;
	ATF_REQUIRE_EQ(EINVAL, cbl_family_register(ctx, &def, NULL, &f2));
	def.abi = 99;
	def.ops = test_ops;
	ATF_REQUIRE_EQ(EINVAL, cbl_family_register(ctx, &def, NULL, &f2));

	ATF_REQUIRE_EQ(0, cbl_family_unregister(f1));
	cbl_ctx_free(ctx);
}

static void *
loop_thread(void *arg)
{

	(void)cbl_loop_run(arg);
	return (NULL);
}

struct fixture {
	cbl_ctx			*sctx;
	cbl_ctx			*cctx;
	struct test_server	 ts;
	cbl_conn		*c;
	cbl_family		*fam;
	uint16_t		 id;
};

static void
setup(struct fixture *f)
{

	f->sctx = test_ctx();
	f->cctx = test_ctx();
	ATF_REQUIRE_EQ(0, cbl_family_register(f->sctx, &test_def, NULL,
	    &f->fam));
	f->id = cbl_family_id(f->fam);
	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(f->sctx, CBL_LIM_SENDQ_BYTES,
	    64 * 1024));
	test_server_start(&f->ts, f->sctx, "tcp://127.0.0.1:0",
	    CBL_PLAINTEXT);
	ATF_REQUIRE_EQ(0, cbl_conn_new(f->cctx, f->ts.uri, CBL_PLAINTEXT,
	    &f->c));
	ATF_REQUIRE_EQ(0, cbl_conn_connect(f->c));
}

static void
teardown(struct fixture *f)
{

	if (f->c != NULL)
		cbl_conn_free(f->c);
	test_server_stop(&f->ts);
	ATF_REQUIRE_EQ(0, cbl_family_unregister(f->fam));
	cbl_ctx_free(f->sctx);
	cbl_ctx_free(f->cctx);
}

ATF_TC_WITHOUT_HEAD(control_family);
ATF_TC_BODY(control_family, tc)
{
	struct fixture f;
	cbl_family_info *info;
	uint32_t gid, flags;

	setup(&f);
	ATF_REQUIRE_EQ(0, cbl_resolve(f.c, "test", &info));
	ATF_REQUIRE_EQ(f.id, cbl_family_info_id(info));
	ATF_REQUIRE_EQ(3, cbl_family_info_version(info));
	ATF_REQUIRE_STREQ("test", cbl_family_info_name(info));
	ATF_REQUIRE_EQ(nitems(test_ops), cbl_family_info_nops(info));
	ATF_REQUIRE_EQ(0, cbl_family_info_op(info, T_LIST, &flags));
	ATF_REQUIRE_EQ(CBL_OPF_DO | CBL_OPF_DUMP, flags);
	ATF_REQUIRE_EQ(ENOENT, cbl_family_info_op(info, 99, &flags));
	ATF_REQUIRE_EQ(0, cbl_family_info_group(info, "audit", &gid));
	ATF_REQUIRE_EQ(cbl_family_group_id(f.fam, 1), gid);
	ATF_REQUIRE_EQ(ENOENT, cbl_family_info_group(info, "nope", &gid));
	cbl_family_info_free(info);

	ATF_REQUIRE_EQ(0, cbl_resolve(f.c, "ctrl", &info));
	ATF_REQUIRE_EQ(0, cbl_family_info_id(info));
	ATF_REQUIRE_EQ(0, cbl_family_info_group(info, "notify", &gid));
	ATF_REQUIRE_EQ(CBL_CTRL_GROUP_NOTIFY, gid);
	cbl_family_info_free(info);

	ATF_REQUIRE_EQ(ENOENT, cbl_resolve(f.c, "nosuch", &info));
	ATF_REQUIRE_EQ(0, cbl_ping(f.c, 2000));
	ATF_REQUIRE_EQ(0, cbl_hello(f.c));
	teardown(&f);
}

ATF_TC_WITHOUT_HEAD(dispatch);
ATF_TC_BODY(dispatch, tc)
{
	struct cbl_path_elem path[4];
	struct fixture f;
	cbl_msg *req, *rsp;
	const void *ck;
	const char *s;
	size_t len;

	setup(&f);
	/* Do with a reply. */
	cbl_msg_new(f.cctx, f.id, T_ECHO, 0, &req);
	cbl_put_str(req, TA_VAL, "ping");
	ATF_REQUIRE_EQ(0, cbl_request(f.c, req, &rsp, 2000));
	ATF_REQUIRE_EQ(0, cbl_attr_str(rsp, cbl_msg_attr(rsp, TA_VAL), &s));
	ATF_REQUIRE_STREQ("ping", s);
	cbl_msg_free(rsp);

	/* Policy failures carry the attribute path. */
	cbl_msg_new(f.cctx, f.id, T_ECHO, 0, &req);
	ATF_REQUIRE_EQ(EINVAL, cbl_request(f.c, req, &rsp, 2000));
	ATF_REQUIRE_EQ(TA_VAL, cbl_msg_err_miss_type(rsp));
	cbl_msg_free(rsp);
	cbl_msg_new(f.cctx, f.id, T_ECHO, 0, &req);
	cbl_put_str(req, TA_VAL, "this is far too long");
	ATF_REQUIRE_EQ(ERANGE, cbl_request(f.c, req, &rsp, 2000));
	ATF_REQUIRE_EQ(1, cbl_msg_err_path(rsp, path, 4));
	ATF_REQUIRE_EQ(TA_VAL, path[0].v);
	ATF_REQUIRE_STREQ("length out of range", cbl_msg_err_str(rsp));
	cbl_msg_free(rsp);

	/* Handler-set extended ack and cookie. */
	cbl_msg_new(f.cctx, f.id, T_FAIL, 0, &req);
	ATF_REQUIRE_EQ(EPERM, cbl_request(f.c, req, &rsp, 2000));
	ATF_REQUIRE_STREQ("handler says no", cbl_msg_err_str(rsp));
	ATF_REQUIRE_EQ(0, cbl_msg_err_cookie(rsp, &ck, &len));
	ATF_REQUIRE(len == 3 && memcmp(ck, "xyz", 3) == 0);
	cbl_msg_free(rsp);

	/* Command errors. */
	cbl_msg_new(f.cctx, f.id, 99, 0, &req);
	ATF_REQUIRE_EQ(EOPNOTSUPP, cbl_request(f.c, req, &rsp, 2000));
	cbl_msg_free(rsp);
	cbl_msg_new(f.cctx, f.id, T_DUMPONLY, 0, &req);
	ATF_REQUIRE_EQ(EOPNOTSUPP, cbl_request(f.c, req, &rsp, 2000));
	cbl_msg_free(rsp);
	cbl_msg_new(f.cctx, f.id, T_ECHO, CBL_F_DUMP, &req);
	cbl_put_str(req, TA_VAL, "x");
	ATF_REQUIRE_EQ(EOPNOTSUPP, cbl_request(f.c, req, &rsp, 2000));
	cbl_msg_free(rsp);
	/* Plaintext TCP peers are not authenticated. */
	cbl_msg_new(f.cctx, f.id, T_SECRET, 0, &req);
	ATF_REQUIRE_EQ(EACCES, cbl_request(f.c, req, &rsp, 2000));
	cbl_msg_free(rsp);
	teardown(&f);
}

struct dump_rec {
	atomic_int	 items;
	atomic_int	 finals;
	atomic_int	 error;
	atomic_uint	 next;
	atomic_bool	 order_ok;
};

static void
dump_cb(cbl_conn *conn __unused, cbl_msg *m, bool final, int error,
    void *arg)
{
	struct dump_rec *r = arg;
	uint64_t idx;

	if (final) {
		r->error = error;
		r->finals++;
		return;
	}
	ATF_REQUIRE_EQ(CBL_F_MULTI, cbl_msg_flags(m));
	(void)cbl_attr_uint(cbl_msg_attr(m, TA_IDX), &idx);
	if (idx != r->next)
		r->order_ok = false;
	r->next++;
	r->items++;
}

static void
drive_until(cbl_conn *c, atomic_int *flag, int ms)
{
	struct timespec t0, t1;
	struct pollfd pfd;
	int events, timeout;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (;;) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		if (*flag != 0 || (t1.tv_sec - t0.tv_sec) * 1000 +
		    (t1.tv_nsec - t0.tv_nsec) / 1000000 >= ms)
			break;
		cbl_conn_interest(c, &events, &timeout);
		pfd.fd = cbl_conn_fd(c);
		pfd.events = POLLIN | ((events & CBL_EV_WRITE) ? POLLOUT : 0);
		(void)poll(&pfd, 1, 10);
		(void)cbl_conn_process(c,
		    ((pfd.revents & POLLIN) ? CBL_EV_READ : 0) |
		    ((pfd.revents & POLLOUT) ? CBL_EV_WRITE : 0));
	}
}

/*
 * A large dump through a small send queue: the server pauses and resumes
 * while the client consumes, and everything arrives in order.
 */
ATF_TC_WITHOUT_HEAD(dump_backpressure);
ATF_TC_BODY(dump_backpressure, tc)
{
	struct fixture f;
	struct dump_rec r = { .order_ok = true };
	cbl_msg *req;

	setup(&f);
	cbl_msg_new(f.cctx, f.id, T_LIST, CBL_F_DUMP, &req);
	cbl_put_uint(req, TA_N, 5000);
	ATF_REQUIRE_EQ(0, cbl_request_async(f.c, req, dump_cb, &r));
	drive_until(f.c, &r.finals, 20000);
	ATF_REQUIRE_EQ(1, r.finals);
	ATF_REQUIRE_EQ(0, r.error);
	ATF_REQUIRE_EQ(5000, r.items);
	ATF_REQUIRE(r.order_ok);

	/* Empty dump: just DONE. */
	memset(&r, 0, sizeof(r));
	r.order_ok = true;
	cbl_msg_new(f.cctx, f.id, T_LIST, CBL_F_DUMP, &req);
	cbl_put_uint(req, TA_N, 0);
	ATF_REQUIRE_EQ(0, cbl_request_async(f.c, req, dump_cb, &r));
	drive_until(f.c, &r.finals, 5000);
	ATF_REQUIRE_EQ(1, r.finals);
	ATF_REQUIRE_EQ(0, r.items);

	/* Policy failure on a dump ends it with ERROR|MULTI|DONE. */
	memset(&r, 0, sizeof(r));
	cbl_msg_new(f.cctx, f.id, T_LIST, CBL_F_DUMP, &req);
	cbl_put_str(req, TA_N, "x");
	ATF_REQUIRE_EQ(0, cbl_request_async(f.c, req, dump_cb, &r));
	drive_until(f.c, &r.finals, 5000);
	ATF_REQUIRE_EQ(1, r.finals);
	ATF_REQUIRE_EQ(EINVAL, r.error);

	/* ctrl getfamily dump lists ctrl and test. */
	memset(&r, 0, sizeof(r));
	r.order_ok = true;
	cbl_msg_new(f.cctx, CBL_CTRL_FAMILY, 1, CBL_F_DUMP, &req);
	ATF_REQUIRE_EQ(0, cbl_request_async(f.c, req, dump_cb, &r));
	drive_until(f.c, &r.finals, 5000);
	ATF_REQUIRE_EQ(1, r.finals);
	ATF_REQUIRE_EQ(2, r.items);
	teardown(&f);
}

struct defer_rec {
	atomic_int	 done;
	atomic_int	 order[4];
	atomic_int	 n;
};

static void
defer_cb(cbl_conn *conn __unused, cbl_msg *m, bool final,
    int error __unused, void *arg)
{
	struct defer_rec *r = arg;
	uint64_t idx;

	if (!final && m != NULL) {
		(void)cbl_attr_uint(cbl_msg_attr(m, TA_IDX), &idx);
		r->order[r->n++] = (int)idx;
	}
	if (final)
		r->done++;
}

/* Deferred requests complete from other threads, out of order. */
ATF_TC_WITHOUT_HEAD(deferred_out_of_order);
ATF_TC_BODY(deferred_out_of_order, tc)
{
	static const int delay[4] = { 400, 50, 250, 150 };
	struct fixture f;
	struct defer_rec r = {};
	atomic_int all = 0;
	cbl_msg *req;

	setup(&f);
	for (int i = 0; i < 4; i++) {
		cbl_msg_new(f.cctx, f.id, T_DEFER, 0, &req);
		cbl_put_uint(req, TA_DELAY, (uint64_t)delay[i]);
		cbl_put_uint(req, TA_IDX, (uint64_t)i);
		ATF_REQUIRE_EQ(0, cbl_request_async(f.c, req, defer_cb, &r));
	}
	for (int i = 0; i < 300 && r.done < 4; i++)
		drive_until(f.c, &all, 10);
	ATF_REQUIRE_EQ(4, r.done);
	ATF_REQUIRE_EQ(1, r.order[0]);
	ATF_REQUIRE_EQ(3, r.order[1]);
	ATF_REQUIRE_EQ(2, r.order[2]);
	ATF_REQUIRE_EQ(0, r.order[3]);
	teardown(&f);
}

ATF_TC_WITHOUT_HEAD(deferred_completed_early);
ATF_TC_BODY(deferred_completed_early, tc)
{
	struct fixture f;
	cbl_msg *req;

	setup(&f);
	for (int i = 0; i < 20; i++) {
		ATF_REQUIRE_EQ(0, cbl_msg_new(f.cctx, f.id, T_DEFERFAST, 0,
		    &req));
		ATF_REQUIRE_EQ(0, cbl_request(f.c, req, NULL, 3000));
	}
	teardown(&f);
}

/*
 * A deferred request whose client goes away is cancelled: the callback
 * runs, cbl_req_cancelled() says so, and cbl_req_complete() releases it.
 */
static void
ignore_reply(cbl_conn *conn __unused, cbl_msg *m __unused, bool final __unused,
    int error __unused, void *arg __unused)
{
}

ATF_TC_WITHOUT_HEAD(deferred_cancelled);
ATF_TC_BODY(deferred_cancelled, tc)
{
	struct fixture f;
	atomic_int none = 0;
	cbl_msg *req;

	setup(&f);
	ATF_REQUIRE_EQ(0, cbl_msg_new(f.cctx, f.id, T_FOREVER, 0, &req));
	ATF_REQUIRE_EQ(0, cbl_request_async(f.c, req, ignore_reply, NULL));
	drive_until(f.c, &none, 200);	/* the server defers it */
	cbl_conn_free(f.c);
	f.c = NULL;
	for (int i = 0; i < 300 && forever.cancelled == 0; i++)
		usleep(10000);
	ATF_REQUIRE_EQ(1, forever.cancelled);
	ATF_REQUIRE(cbl_req_cancelled(forever.req));
	ATF_REQUIRE_EQ(0, cbl_req_complete(forever.req, 0));
	teardown(&f);
}

/*
 * Read backpressure: a client that sends many requests and does not read
 * its replies is not read either, instead of having replies dropped; once
 * it reads, every reply is there, in order.
 */
#define	FLOOD_N		20000		/* 20 MB of replies */

struct flood {
	int		 fd;
	uint16_t	 fam;
};

static void *
flood_writer(void *arg)
{
	struct flood *fl = arg;
	unsigned char *buf, *p;
	size_t len;
	int n;

	ATF_REQUIRE((buf = malloc(1000 * 32)) != NULL);
	for (uint32_t seq = 1; seq <= FLOOD_N; ) {
		p = buf;
		for (n = 0; n < 1000 && seq <= FLOOD_N; n++, seq++)
			p += mkframe(p, 32, fl->fam, T_BIG, CBL_F_REQUEST,
			    seq, 0, "A0");
		len = (size_t)(p - buf);
		for (size_t off = 0; off < len; ) {
			ssize_t w = write(fl->fd, buf + off, len - off);

			if (w <= 0) {
				free(buf);
				return (NULL);
			}
			off += (size_t)w;
		}
	}
	free(buf);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(unread_replies_kept);
ATF_TC_BODY(unread_replies_kept, tc)
{
	struct sockaddr_in sin = { .sin_len = sizeof(sin),
	    .sin_family = AF_INET };
	struct fixture f;
	struct flood fl;
	pthread_t thr;
	cbl_msg *m;
	uint32_t want = 1;
	int small = 4096;

	setup(&f);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = htons((uint16_t)atoi(strrchr(f.ts.uri, ':') + 1));
	fl.fam = f.id;
	ATF_REQUIRE((fl.fd = socket(AF_INET, SOCK_STREAM, 0)) != -1);
	ATF_REQUIRE_EQ(0, setsockopt(fl.fd, SOL_SOCKET, SO_RCVBUF, &small,
	    sizeof(small)));
	ATF_REQUIRE_EQ(0, connect(fl.fd, (struct sockaddr *)&sin,
	    sizeof(sin)));
	ATF_REQUIRE_EQ(0, pthread_create(&thr, NULL, flood_writer, &fl));
	usleep(500000);		/* replies pile up on the server */
	while (want <= FLOOD_N && (m = raw_read_msg(f.cctx, fl.fd)) != NULL) {
		ATF_REQUIRE_EQ_MSG(want, cbl_msg_seq(m), "reply %u missing",
		    want);
		ATF_REQUIRE_EQ_MSG(0, cbl_msg_err_code(m), "reply %u: error %d",
		    want, cbl_msg_err_code(m));
		cbl_msg_free(m);
		want++;
	}
	ATF_REQUIRE_EQ(FLOOD_N + 1, want);
	pthread_join(thr, NULL);
	close(fl.fd);
	teardown(&f);
}

/*
 * A client dump consumed more slowly than it arrives: the connection stops
 * reading while the dump's queue is full, and every item arrives.
 */
struct loop_thr {
	cbl_loop	*loop;
	pthread_t	 thr;
};

static void *
loop_main(void *arg)
{
	struct loop_thr *lt = arg;

	(void)cbl_loop_run(lt->loop);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(slow_dump_consumer);
ATF_TC_BODY(slow_dump_consumer, tc)
{
	struct fixture f;
	struct loop_thr lt;
	cbl_dump *d;
	cbl_msg *req, *item;
	uint64_t idx;
	int n = 0, error;

	memset(&f, 0, sizeof(f));
	f.sctx = test_ctx();
	f.cctx = test_ctx();
	ATF_REQUIRE_EQ(0, cbl_family_register(f.sctx, &test_def, NULL,
	    &f.fam));
	f.id = cbl_family_id(f.fam);
	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(f.cctx, CBL_LIM_SENDQ_BYTES,
	    64 * 1024));		/* the smallest: the dump is 6x that */
	test_server_start(&f.ts, f.sctx, "tcp://127.0.0.1:0",
	    CBL_PLAINTEXT);
	ATF_REQUIRE_EQ(0, cbl_conn_new(f.cctx, f.ts.uri, CBL_PLAINTEXT, &f.c));
	ATF_REQUIRE_EQ(0, cbl_conn_connect(f.c));
	ATF_REQUIRE_EQ(0, cbl_loop_new(f.cctx, &lt.loop));
	ATF_REQUIRE_EQ(0, cbl_conn_attach(f.c, lt.loop));
	ATF_REQUIRE_EQ(0, pthread_create(&lt.thr, NULL, loop_main, &lt));
	ATF_REQUIRE_EQ(0, cbl_msg_new(f.cctx, f.id, T_LIST, CBL_F_DUMP, &req));
	cbl_put_uint(req, TA_N, 6000);
	ATF_REQUIRE_EQ(0, cbl_dump_start(f.c, req, &d));
	while ((error = cbl_dump_next(d, &item)) == 0 && item != NULL) {
		ATF_REQUIRE_EQ(0, cbl_attr_uint(cbl_msg_attr(item, TA_IDX),
		    &idx));
		ATF_REQUIRE_EQ((uint64_t)n, idx);
		if (++n % 100 == 0)
			usleep(20000);	/* a slow consumer */
	}
	ATF_REQUIRE_EQ_MSG(0, error, "dump: %s", strerror(error));
	ATF_REQUIRE_EQ(6000, n);
	cbl_dump_free(d);
	cbl_conn_free(f.c);
	f.c = NULL;
	cbl_loop_stop(lt.loop);
	pthread_join(lt.thr, NULL);
	cbl_loop_free(lt.loop);
	teardown(&f);
}

/* max_inflight: excess requests get EAGAIN while handlers are deferred. */
ATF_TC_WITHOUT_HEAD(inflight_limit);
ATF_TC_BODY(inflight_limit, tc)
{
	struct fixture f;
	struct defer_rec r = {};
	atomic_int all = 0;
	cbl_msg *req, *rsp;

	f.sctx = test_ctx();
	f.cctx = test_ctx();
	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(f.sctx, CBL_LIM_MAX_INFLIGHT, 2));
	ATF_REQUIRE_EQ(0, cbl_family_register(f.sctx, &test_def, NULL,
	    &f.fam));
	f.id = cbl_family_id(f.fam);
	test_server_start(&f.ts, f.sctx, "tcp://127.0.0.1:0", CBL_PLAINTEXT);
	ATF_REQUIRE_EQ(0, cbl_conn_new(f.cctx, f.ts.uri, CBL_PLAINTEXT, &f.c));
	ATF_REQUIRE_EQ(0, cbl_conn_connect(f.c));
	for (int i = 0; i < 2; i++) {
		cbl_msg_new(f.cctx, f.id, T_DEFER, 0, &req);
		cbl_put_uint(req, TA_DELAY, 300);
		ATF_REQUIRE_EQ(0, cbl_request_async(f.c, req, defer_cb, &r));
	}
	drive_until(f.c, &all, 100);
	cbl_msg_new(f.cctx, f.id, T_ECHO, 0, &req);
	cbl_put_str(req, TA_VAL, "x");
	ATF_REQUIRE_EQ(EAGAIN, cbl_request(f.c, req, &rsp, 2000));
	cbl_msg_free(rsp);
	for (int i = 0; i < 300 && r.done < 2; i++)
		drive_until(f.c, &all, 10);
	ATF_REQUIRE_EQ(2, r.done);
	teardown(&f);
}

/* The synchronous dump iterator, with and without a loop thread. */
static int
run_dump(struct fixture *f, uint64_t n, uint64_t fail_at, int *items)
{
	cbl_msg *req, *item;
	cbl_dump *d;
	uint64_t idx;
	int error;

	cbl_msg_new(f->cctx, f->id, T_LIST, 0, &req);
	cbl_put_uint(req, TA_N, n);
	if (fail_at != UINT64_MAX)
		cbl_put_uint(req, TA_DELAY, fail_at);
	ATF_REQUIRE_EQ(0, cbl_dump_start(f->c, req, &d));
	*items = 0;
	while ((error = cbl_dump_next(d, &item)) == 0 && item != NULL) {
		ATF_REQUIRE_EQ(0, cbl_attr_uint(cbl_msg_attr(item, TA_IDX),
		    &idx));
		ATF_REQUIRE_EQ((uint64_t)*items, idx);
		(*items)++;
	}
	if (error != 0) {
		ATF_REQUIRE(cbl_dump_error(d) != NULL);
		ATF_REQUIRE_STREQ("dump failed part-way",
		    cbl_msg_err_str(cbl_dump_error(d)));
	}
	cbl_dump_free(d);
	return (error);
}

ATF_TC_WITHOUT_HEAD(dump_iterator);
ATF_TC_BODY(dump_iterator, tc)
{
	struct fixture f;
	cbl_msg *req, *item;
	cbl_loop *loop;
	cbl_dump *d;
	pthread_t thr;
	int items;

	setup(&f);
	/* Driving the socket ourselves. */
	ATF_REQUIRE_EQ(0, run_dump(&f, 3000, UINT64_MAX, &items));
	ATF_REQUIRE_EQ(3000, items);
	ATF_REQUIRE_EQ(EIO, run_dump(&f, 100, 40, &items));
	ATF_REQUIRE_EQ(40, items);
	/* Abandoned half-way: freeing must be safe. */
	cbl_msg_new(f.cctx, f.id, T_LIST, 0, &req);
	cbl_put_uint(req, TA_N, 500);
	ATF_REQUIRE_EQ(0, cbl_dump_start(f.c, req, &d));
	ATF_REQUIRE_EQ(0, cbl_dump_next(d, &item));
	ATF_REQUIRE(item != NULL);
	cbl_dump_free(d);
	ATF_REQUIRE_EQ(0, cbl_ping(f.c, 2000));

	/* With a loop thread running the connection. */
	ATF_REQUIRE_EQ(0, cbl_loop_new(f.cctx, &loop));
	ATF_REQUIRE_EQ(0, cbl_conn_attach(f.c, loop));
	ATF_REQUIRE_EQ(0, pthread_create(&thr, NULL, loop_thread, loop));
	ATF_REQUIRE_EQ(0, run_dump(&f, 3000, UINT64_MAX, &items));
	ATF_REQUIRE_EQ(3000, items);
	ATF_REQUIRE_EQ(EIO, run_dump(&f, 100, 7, &items));
	ATF_REQUIRE_EQ(7, items);
	cbl_msg_new(f.cctx, f.id, T_LIST, 0, &req);
	cbl_put_uint(req, TA_N, 500);
	ATF_REQUIRE_EQ(0, cbl_dump_start(f.c, req, &d));
	cbl_dump_free(d);
	ATF_REQUIRE_EQ(0, cbl_ping(f.c, 2000));
	cbl_loop_stop(loop);
	pthread_join(thr, NULL);
	cbl_conn_free(f.c);
	f.c = NULL;
	cbl_loop_free(loop);
	teardown(&f);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, dump_iterator);

	ATF_TP_ADD_TC(tp, registry);
	ATF_TP_ADD_TC(tp, control_family);
	ATF_TP_ADD_TC(tp, dispatch);
	ATF_TP_ADD_TC(tp, dump_backpressure);
	ATF_TP_ADD_TC(tp, deferred_out_of_order);
	ATF_TP_ADD_TC(tp, deferred_completed_early);
	ATF_TP_ADD_TC(tp, deferred_cancelled);
	ATF_TP_ADD_TC(tp, unread_replies_kept);
	ATF_TP_ADD_TC(tp, slow_dump_consumer);
	ATF_TP_ADD_TC(tp, inflight_limit);
	return (atf_no_error());
}
