/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Code generated from golden/types.yaml at build time, compiled with
 * WARNS=6, exercised end to end: struct encode/decode round trips,
 * generated policies, builders, and generated client wrappers talking to
 * generated server trampolines over loopback TCP.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <atf-c.h>
#include <errno.h>
#include <math.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include "types.h"

static cbl_ctx *
ctx_new(void)
{
	cbl_ctx *ctx;

	ATF_REQUIRE_EQ(0, cbl_ctx_new(&ctx));
	return (ctx);
}

static cbl_msg *
reencode(cbl_ctx *ctx, cbl_msg *msg)
{
	const void *f;
	cbl_msg *rx;
	size_t len;

	ATF_REQUIRE_EQ(0, cbl_msg_encode(msg, &f, &len));
	ATF_REQUIRE_EQ(0, cbl_frame_decode(ctx, f, len, NULL, &rx));
	cbl_msg_free(msg);
	return (rx);
}

/* A fully populated value of every field. */
static const struct types_point pts[] = {
	{ .has_x = true, .x = 1, .has_y = true, .y = -1 },
	{ .has_x = true, .x = INT64_MIN },
};
static const struct types_node leaves[] = {
	{ .label = "leaf-a" },
	{ .label = "leaf-b" },
};
static const struct types_node mid = {
	.label = "mid", .kids = { .n = 2, .v = leaves } };
static const struct types_node root = {
	.label = "root", .kids = { .n = 1, .v = &mid } };
static const char *const nm[] = { "a", "bb", "ccc" };
static const int32_t nums[] = { -7, 0, 7 };
static const uint8_t blob[] = { 1, 2, 3 };
static const uint8_t digest[] = { 9, 8, 7, 6 };

static void
fill(struct types_types *t)
{

	memset(t, 0, sizeof(*t));
	t->has_u8 = true; t->u8 = 200;
	t->has_u16 = true; t->u16 = 1000;
	t->has_u32 = true; t->u32 = TYPES_COLOR_GREEN;
	t->has_u64 = true; t->u64 = UINT64_MAX;
	t->has_s8 = true; t->s8 = -100;
	t->has_s16 = true; t->s16 = INT16_MIN;
	t->has_s32 = true; t->s32 = -5;
	t->has_s64 = true; t->s64 = INT64_MIN;
	t->has_on = true; t->on = false;
	t->marker = true;
	t->name = "hello";
	t->blob = (struct cbl_bytes){ blob, sizeof(blob) };
	t->digest = (struct cbl_bytes){ digest, sizeof(digest) };
	t->has_ratio = true; t->ratio = 0.25;
	t->has_perms = true;
	t->perms = TYPES_PERM_READ | TYPES_PERM_EXEC;
	t->point = &pts[0];
	t->points.n = 2; t->points.v = pts;
	t->names.n = 3; t->names.v = nm;
	t->nums.n = 3; t->nums.v = nums;
	t->tree = &root;
	t->has_value = true; t->value = 65535;
	t->has_after = true; t->after = 0;
}

static void
check(const struct types_types *t)
{

	ATF_REQUIRE(t->has_u8 && t->u8 == 200);
	ATF_REQUIRE(t->has_u16 && t->u16 == 1000);
	ATF_REQUIRE(t->has_u32 && t->u32 == TYPES_COLOR_GREEN);
	ATF_REQUIRE(t->has_u64 && t->u64 == UINT64_MAX);
	ATF_REQUIRE(t->has_s8 && t->s8 == -100);
	ATF_REQUIRE(t->has_s16 && t->s16 == INT16_MIN);
	ATF_REQUIRE(t->has_s32 && t->s32 == -5);
	ATF_REQUIRE(t->has_s64 && t->s64 == INT64_MIN);
	ATF_REQUIRE(t->has_on && !t->on);
	ATF_REQUIRE(t->marker);
	ATF_REQUIRE_STREQ("hello", t->name);
	ATF_REQUIRE(t->blob.len == 3 && memcmp(t->blob.p, blob, 3) == 0);
	ATF_REQUIRE(t->digest.len == 4);
	ATF_REQUIRE(t->has_ratio && t->ratio == 0.25);
	ATF_REQUIRE(t->has_perms &&
	    t->perms == (TYPES_PERM_READ | TYPES_PERM_EXEC));
	ATF_REQUIRE(t->point != NULL && t->point->x == 1 && t->point->y == -1);
	ATF_REQUIRE_EQ(2, t->points.n);
	ATF_REQUIRE(t->points.v[1].has_x && t->points.v[1].x == INT64_MIN);
	ATF_REQUIRE(!t->points.v[1].has_y);
	ATF_REQUIRE_EQ(3, t->names.n);
	ATF_REQUIRE_STREQ("ccc", t->names.v[2]);
	ATF_REQUIRE_EQ(3, t->nums.n);
	ATF_REQUIRE_EQ(-7, t->nums.v[0]);
	ATF_REQUIRE_STREQ("root", t->tree->label);
	ATF_REQUIRE_EQ(1, t->tree->kids.n);
	ATF_REQUIRE_EQ(2, t->tree->kids.v[0].kids.n);
	ATF_REQUIRE_STREQ("leaf-b", t->tree->kids.v[0].kids.v[1].label);
	ATF_REQUIRE(t->has_value && t->value == 65535);
	ATF_REQUIRE(t->has_after && t->after == 0);
}

ATF_TC_WITHOUT_HEAD(struct_roundtrip);
ATF_TC_BODY(struct_roundtrip, tc)
{
	cbl_ctx *ctx = ctx_new();
	struct types_types in, out;
	cbl_msg *msg;

	fill(&in);
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 1, 1, 0, &msg));
	ATF_REQUIRE_EQ(0, types_types_put_fields(msg, &in));
	msg = reencode(ctx, msg);
	ATF_REQUIRE_EQ(0, types_types_parse(msg, cbl_msg_body(msg), &out));
	check(&out);
	/* The full-set policy accepts it. */
	ATF_REQUIRE_EQ(0, cbl_validate(cbl_msg_body(msg), &types_types_policy,
	    NULL));
	ATF_REQUIRE_EQ(0, cbl_policy_set_check(&types_types_policy));
	ATF_REQUIRE_EQ(0, cbl_parser_check(&types_types_parser));
	cbl_msg_free(msg);

	/* Explicit ids: "value" is 100 and "after" 101. */
	ATF_REQUIRE_EQ(100, TYPES_A_VALUE);
	ATF_REQUIRE_EQ(101, TYPES_A_AFTER);
	ATF_REQUIRE_EQ(101, TYPES_A_MAX);
	ATF_REQUIRE_EQ(10, TYPES_CMD_LIST);
	ATF_REQUIRE_EQ(11, TYPES_CMD_CHANGED);
	ATF_REQUIRE_EQ(5, TYPES_COLOR_GREEN);
	ATF_REQUIRE_EQ(6, TYPES_COLOR_BLUE);
	ATF_REQUIRE_EQ(UINT64_C(1) << 7, TYPES_PERM_EXEC);
	ATF_REQUIRE_EQ(-100, TYPES_NEG_LIMIT);
	cbl_ctx_free(ctx);
}

ATF_TC_WITHOUT_HEAD(builders);
ATF_TC_BODY(builders, tc)
{
	cbl_ctx *ctx = ctx_new();
	struct types_types out;
	cbl_msg *msg;

	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 1, 1, 0, &msg));
	ATF_REQUIRE_EQ(0, types_put_u8(msg, 7));
	ATF_REQUIRE_EQ(0, types_put_s64(msg, -9));
	ATF_REQUIRE_EQ(0, types_put_marker(msg));
	ATF_REQUIRE_EQ(0, types_put_blob(msg, "xy", 2));
	ATF_REQUIRE_EQ(0, types_put_names(msg, nm, 2));
	ATF_REQUIRE_EQ(0, types_put_points(msg, pts, 1));
	ATF_REQUIRE_EQ(0, types_put_tree(msg, &mid));
	ATF_REQUIRE_EQ(0, types_put_ratio(msg, -1.5));
	msg = reencode(ctx, msg);
	ATF_REQUIRE_EQ(0, types_types_parse(msg, cbl_msg_body(msg), &out));
	ATF_REQUIRE(out.has_u8 && out.u8 == 7);
	ATF_REQUIRE(out.has_s64 && out.s64 == -9);
	ATF_REQUIRE(out.marker);
	ATF_REQUIRE_EQ(2, out.blob.len);
	ATF_REQUIRE_EQ(2, out.names.n);
	ATF_REQUIRE_EQ(1, out.points.n);
	ATF_REQUIRE_EQ(2, out.tree->kids.n);
	ATF_REQUIRE(out.ratio == -1.5);
	ATF_REQUIRE(!out.has_u16 && out.name == NULL && out.point == NULL);
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

/* Generated policies: each mutation hits the expected check. */
ATF_TC_WITHOUT_HEAD(policies);
ATF_TC_BODY(policies, tc)
{
	static const struct types_point nox = { .has_y = true, .y = 1 };
	static const char *const toolong[] = { "123456789" };
	cbl_ctx *ctx = ctx_new();
	struct types_types t;
	struct cbl_verr ve;
	cbl_msg *msg;
	int want, got;

	for (int mut = 0; mut <= 9; mut++) {
		fill(&t);
		want = 0;
		switch (mut) {
		case 1: t.u16 = 9; want = ERANGE; break;
		case 2: t.u32 = 3; want = EINVAL; break;	/* bad color */
		case 3: t.perms = 4; want = EINVAL; break;	/* bad bit */
		case 4: t.name = NULL; want = EINVAL; break;	/* required */
		case 5: t.digest.len = 3; want = ERANGE; break;
		case 6: t.names.n = 0; want = 0; break;	/* absent is fine */
		case 7: t.names.v = toolong; t.names.n = 1; want = ERANGE;
			break;
		case 8: t.point = &nox; want = EINVAL; break;	/* x required */
		case 9: t.s8 = -101; want = ERANGE; break;	/* neg-limit */
		}
		ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 1, 1, 0, &msg));
		ATF_REQUIRE_EQ(0, types_types_put_fields(msg, &t));
		msg = reencode(ctx, msg);
		got = cbl_validate(cbl_msg_body(msg), &types_echo_req_policy,
		    &ve);
		ATF_CHECK_EQ_MSG(want, got, "mutation %d: %d", mut, got);
		if (mut == 4)
			ATF_CHECK_EQ(TYPES_A_NAME, ve.miss_type);
		if (mut == 8) {
			ATF_CHECK_EQ(TYPES_POINT_A_X, ve.miss_type);
			ATF_CHECK_EQ(1, ve.pathlen);
			ATF_CHECK_EQ(TYPES_A_POINT, ve.path[0].v);
		}
		cbl_msg_free(msg);
	}
	cbl_ctx_free(ctx);
}

/* Server handlers (prototypes generated in types.h). */
int
types_echo_doit(cbl_req *req, const struct types_echo_req *rq,
    void *arg __unused)
{
	struct types_echo_rsp rsp = {
		.has_u8 = rq->has_u8, .u8 = rq->u8,
		.has_u16 = rq->has_u16, .u16 = rq->u16,
		.has_u32 = rq->has_u32, .u32 = rq->u32,
		.has_u64 = rq->has_u64, .u64 = rq->u64,
		.has_s8 = rq->has_s8, .s8 = rq->s8,
		.has_s16 = rq->has_s16, .s16 = rq->s16,
		.has_s32 = rq->has_s32, .s32 = rq->s32,
		.has_s64 = rq->has_s64, .s64 = rq->s64,
		.has_on = rq->has_on, .on = rq->on,
		.marker = rq->marker,
		.name = rq->name,
		.blob = rq->blob,
		.digest = rq->digest,
		.has_ratio = rq->has_ratio, .ratio = rq->ratio,
		.has_perms = rq->has_perms, .perms = rq->perms,
		.point = rq->point,
		.tree = rq->tree,
		.has_value = rq->has_value, .value = rq->value,
		.has_after = rq->has_after, .after = rq->after,
	};

	rsp.points.n = rq->points.n;
	rsp.points.v = rq->points.v;
	rsp.names.n = rq->names.n;
	rsp.names.v = rq->names.v;
	rsp.nums.n = rq->nums.n;
	rsp.nums.v = rq->nums.v;
	return (types_echo_reply(req, &rsp));
}

int
types_poke_doit(cbl_req *req, void *arg __unused)
{
	struct types_poke_rsp rsp = { .has_u8 = true, .u8 = 1 };

	return (types_poke_reply(req, &rsp));
}

int
types_list_doit(cbl_req *req __unused, const struct types_list_req *rq,
    void *arg __unused)
{

	return (rq->u32 == TYPES_COLOR_BLUE ? 0 : ENOENT);
}

int
types_list_dumpit(cbl_req *req, const struct types_list_dump_req *rq,
    struct cbl_dump_state *st, void *arg __unused)
{
	struct types_list_dump_rsp item = { .has_u16 = true,
	    .name = "item" };
	uint64_t n = rq->has_u16 ? rq->u16 : 3;
	int error;

	if (st->pos[0] >= n)
		return (0);
	item.u16 = (uint16_t)st->pos[0]++;
	if ((error = types_list_dump_reply(req, &item)) != 0)
		return (error);
	return (EAGAIN);
}

/* Generated stream handlers, server side. */
static atomic_int uploaded;
static atomic_int upload_closed;

static void
chat_s_data(cbl_stream *s, const struct types_point *p, void *arg __unused)
{
	struct types_point echo = *p;

	echo.has_y = true;
	echo.y = p->x * 2;
	(void)types_chat_server_send(s, &echo);
}

static void
any_s_hclose(cbl_stream *s, void *arg __unused)
{

	(void)cbl_stream_half_close(s);
}

static const struct types_chat_server_cbs chat_s_cbs = {
	.on_data = chat_s_data,
	.on_hclose = any_s_hclose,
};

int
types_chat_stream_open(cbl_req *req __unused, const struct types_chat_req *rq,
    cbl_stream *s, void *arg __unused)
{
	struct types_chat_rsp acc = { .has_u8 = true, .u8 = 42 };

	if (rq->name == NULL || strcmp(rq->name, "alice") != 0)
		return (EACCES);
	return (types_chat_accept(s, &acc, &chat_s_cbs, NULL));
}

static const struct types_feed_server_cbs feed_s_cbs = { 0 };

int
types_feed_stream_open(cbl_req *req __unused, const struct types_feed_req *rq,
    cbl_stream *s, void *arg __unused)
{
	struct types_node n = { 0 };
	int error;

	if ((error = types_feed_accept(s, &feed_s_cbs, NULL)) != 0)
		return (error);
	for (uint16_t i = 0; i < rq->u16; i++) {
		n.label = i % 2 == 0 ? "even" : "odd";
		(void)types_feed_server_send(s, &n);
	}
	(void)cbl_stream_half_close(s);
	return (0);
}

static void
upload_s_data(cbl_stream *s __unused, const struct types_point *p,
    void *arg __unused)
{

	if (p->has_x)
		uploaded++;
}

static void
upload_s_close(cbl_stream *s __unused, int code __unused,
    const char *text __unused, void *arg __unused)
{

	upload_closed++;
}

static const struct types_upload_server_cbs upload_s_cbs = {
	.on_data = upload_s_data,
	.on_hclose = any_s_hclose,
	.on_close = upload_s_close,
};

int
types_upload_stream_open(cbl_req *req __unused,
    const struct types_upload_req *rq __unused, cbl_stream *s,
    void *arg __unused)
{

	return (types_upload_accept(s, &upload_s_cbs, NULL));
}

static void *
loop_thread(void *arg)
{

	(void)cbl_loop_run(arg);
	return (NULL);
}

/* Generated _async wrappers, driven on a loop-less client. */
struct async_rec {
	atomic_int	 n;
	int		 echo_err;
	uint64_t	 u64;
	int		 poke_err;
	bool		 poke_err_msg;	/* cl->err holds the ERROR */
};

static void
echo_done(struct types_client *cl __unused, int error,
    struct types_echo_rsp *rsp, void *arg)
{
	struct async_rec *ar = arg;

	ar->echo_err = error;
	if (rsp != NULL)
		ar->u64 = rsp->u64;
	types_echo_rsp_free(rsp);
	ar->n++;
}

static void
poke_done(struct types_client *cl, int error, struct types_poke_rsp *rsp,
    void *arg)
{
	struct async_rec *ar = arg;

	ar->poke_err = error;
	ar->poke_err_msg = cl->err != NULL;
	types_poke_rsp_free(rsp);
	ar->n++;
}

static void
drive_n(cbl_conn *c, atomic_int *n, int want)
{
	struct pollfd pfd;
	int events, timeout;

	for (int i = 0; i < 500 && *n < want; i++) {
		(void)cbl_conn_interest(c, &events, &timeout);
		pfd.fd = cbl_conn_fd(c);
		pfd.events = POLLIN |
		    ((events & CBL_EV_WRITE) != 0 ? POLLOUT : 0);
		pfd.revents = 0;
		(void)poll(&pfd, 1, 10);
		(void)cbl_conn_process(c,
		    ((pfd.revents & POLLIN) != 0 ? CBL_EV_READ : 0) |
		    ((pfd.revents & POLLOUT) != 0 ? CBL_EV_WRITE : 0));
	}
}

ATF_TC_WITHOUT_HEAD(client_server);
ATF_TC_BODY(client_server, tc)
{
	struct async_rec ar;
	struct types_list_dump_req dq = { .has_u16 = true, .u16 = 12 };
	struct types_list_req lq = { .has_u32 = true, .u32 = TYPES_COLOR_BLUE };
	struct types_list_dump_rsp *item;
	struct types_echo_req req;
	struct types_echo_rsp *rsp;
	struct types_poke_rsp *prsp;
	struct sockaddr_storage ss;
	struct types_types t;
	struct types_client cl;
	cbl_ctx *sctx = ctx_new(), *cctx = ctx_new();
	cbl_listener *l;
	cbl_family *fam;
	cbl_loop *loop;
	cbl_conn *c;
	cbl_dump *d;
	pthread_t thr;
	char uri[64];
	int n;

	ATF_REQUIRE_EQ(0, types_register(sctx, NULL, &fam));
	ATF_REQUIRE_EQ(0, cbl_loop_new(sctx, &loop));
	ATF_REQUIRE_EQ(0, cbl_listener_new(sctx, "tcp://127.0.0.1:0",
	    CBL_PLAINTEXT, &l));
	ATF_REQUIRE_EQ(0, cbl_listener_start(l, loop));
	ATF_REQUIRE_EQ(0, cbl_listener_addr(l, &ss, NULL));
	snprintf(uri, sizeof(uri), "tcp://127.0.0.1:%u",
	    ntohs(((struct sockaddr_in *)&ss)->sin_port));
	ATF_REQUIRE_EQ(0, pthread_create(&thr, NULL, loop_thread, loop));

	ATF_REQUIRE_EQ(0, cbl_conn_new(cctx, uri, CBL_PLAINTEXT, &c));
	ATF_REQUIRE_EQ(0, cbl_conn_connect(c));
	ATF_REQUIRE_EQ(0, types_client_init(&cl, c));
	ATF_REQUIRE_EQ(cbl_family_id(fam), cl.family);
	ATF_REQUIRE_EQ(TYPES_FAMILY_VERSION, cl.version);
	ATF_REQUIRE_EQ(cbl_family_group_id(fam, TYPES_MCGRP_AUDIT),
	    cl.groups[TYPES_MCGRP_AUDIT]);

	/* Every type through the generated client and server. */
	fill(&t);
	memset(&req, 0, sizeof(req));
	req.has_u8 = t.has_u8; req.u8 = t.u8;
	req.has_u16 = t.has_u16; req.u16 = t.u16;
	req.has_u32 = t.has_u32; req.u32 = t.u32;
	req.has_u64 = t.has_u64; req.u64 = t.u64;
	req.has_s8 = t.has_s8; req.s8 = t.s8;
	req.has_s16 = t.has_s16; req.s16 = t.s16;
	req.has_s32 = t.has_s32; req.s32 = t.s32;
	req.has_s64 = t.has_s64; req.s64 = t.s64;
	req.has_on = t.has_on; req.on = t.on;
	req.marker = t.marker;
	req.name = t.name;
	req.blob = t.blob;
	req.digest = t.digest;
	req.has_ratio = t.has_ratio; req.ratio = t.ratio;
	req.has_perms = t.has_perms; req.perms = t.perms;
	req.point = t.point;
	req.points.n = t.points.n; req.points.v = t.points.v;
	req.names.n = t.names.n; req.names.v = t.names.v;
	req.nums.n = t.nums.n; req.nums.v = t.nums.v;
	req.tree = t.tree;
	req.has_value = t.has_value; req.value = t.value;
	req.has_after = t.has_after; req.after = t.after;
	ATF_REQUIRE_EQ(0, types_echo(&cl, &req, &rsp));
	ATF_REQUIRE(rsp->has_u64 && rsp->u64 == UINT64_MAX);
	ATF_REQUIRE_STREQ("leaf-b", rsp->tree->kids.v[0].kids.v[1].label);
	ATF_REQUIRE_EQ(3, rsp->names.n);
	ATF_REQUIRE(rsp->has_s64 && rsp->s64 == INT64_MIN);
	types_echo_rsp_free(rsp);

	/* The generated policy is enforced before the handler. */
	req.name = NULL;
	ATF_REQUIRE_EQ(EINVAL, types_echo(&cl, &req, &rsp));
	ATF_REQUIRE(rsp == NULL);
	ATF_REQUIRE_EQ(TYPES_A_NAME, cbl_msg_err_miss_type(cl.err));

	/* auth: true is enforced on an unauthenticated peer. */
	ATF_REQUIRE_EQ(EACCES, types_poke(&cl, &prsp));

	/* The same calls without waiting: what a client on a loop uses. */
	req.name = t.name;
	memset(&ar, 0, sizeof(ar));
	ATF_REQUIRE_EQ(0, types_echo_async(&cl, &req, echo_done, &ar));
	ATF_REQUIRE_EQ(0, types_poke_async(&cl, poke_done, &ar));
	drive_n(c, &ar.n, 2);
	ATF_REQUIRE_EQ(2, ar.n);
	ATF_REQUIRE_EQ(0, ar.echo_err);
	ATF_REQUIRE_EQ(UINT64_MAX, ar.u64);
	ATF_REQUIRE_EQ(EACCES, ar.poke_err);
	ATF_REQUIRE(ar.poke_err_msg);

	/* do and dump with different request policies. */
	ATF_REQUIRE_EQ(0, types_list(&cl, &lq));
	lq.u32 = TYPES_COLOR_RED;
	ATF_REQUIRE_EQ(ENOENT, types_list(&cl, &lq));
	ATF_REQUIRE_EQ(EINVAL, types_list(&cl, NULL));	/* u32 required */
	ATF_REQUIRE_EQ(0, types_list_dump(&cl, &dq, &d));
	for (n = 0;; n++) {
		ATF_REQUIRE_EQ(0, types_list_dump_next(d, &item));
		if (item == NULL)
			break;
		ATF_REQUIRE_EQ(n, item->u16);
		ATF_REQUIRE_STREQ("item", item->name);
	}
	ATF_REQUIRE_EQ(12, n);
	cbl_dump_free(d);
	ATF_REQUIRE_EQ(0, types_list_dump(&cl, NULL, &d));
	for (n = 0; types_list_dump_next(d, &item) == 0 && item != NULL; n++)
		;
	ATF_REQUIRE_EQ(3, n);
	cbl_dump_free(d);

	types_client_fini(&cl);
	cbl_conn_free(c);
	cbl_loop_stop(loop);
	pthread_join(thr, NULL);
	cbl_listener_free(l);
	cbl_loop_free(loop);
	ATF_REQUIRE_EQ(0, cbl_family_unregister(fam));
	cbl_ctx_free(sctx);
	cbl_ctx_free(cctx);
}

/* Generated stream wrappers and notification handlers, client side. */
struct crec {
	atomic_int	 opened;
	atomic_int	 open_error;
	atomic_int	 accept_u8;
	atomic_int	 data;
	atomic_int	 closed;
	atomic_int	 close_code;
	atomic_int	 ntf;
	int64_t		 last_y;
	char		 last[32];
};

static void
chat_c_open(cbl_stream *s __unused, const struct types_chat_rsp *acc,
    int error, void *arg)
{
	struct crec *r = arg;

	r->open_error = error;
	if (acc != NULL && acc->has_u8)
		r->accept_u8 = acc->u8;
	r->opened++;
}

static void
chat_c_data(cbl_stream *s __unused, const struct types_point *p, void *arg)
{
	struct crec *r = arg;

	r->last_y = p->y;
	r->data++;
}

static void
c_close(cbl_stream *s __unused, int code, const char *text __unused,
    void *arg)
{
	struct crec *r = arg;

	r->close_code = code;
	r->closed++;
}

static const struct types_chat_cbs chat_c_cbs = {
	.on_open = chat_c_open,
	.on_data = chat_c_data,
	.on_close = c_close,
};

static void
plain_c_open(cbl_stream *s __unused, int error, void *arg)
{
	struct crec *r = arg;

	r->open_error = error;
	r->opened++;
}

static void
feed_c_data(cbl_stream *s __unused, const struct types_node *n, void *arg)
{
	struct crec *r = arg;

	strlcpy(r->last, n->label, sizeof(r->last));
	r->data++;
}

static const struct types_feed_cbs feed_c_cbs = {
	.on_open = plain_c_open,
	.on_data = feed_c_data,
	.on_close = c_close,
};

static const struct types_upload_cbs upload_c_cbs = {
	.on_open = plain_c_open,
	.on_close = c_close,
};

static void
changed_ntf(const struct types_changed_ntf *n, void *arg)
{
	struct crec *r = arg;

	if (n->name != NULL && n->has_u32 && n->u32 == TYPES_COLOR_BLUE)
		strlcpy(r->last, n->name, sizeof(r->last));
	r->ntf++;
}

static void
pump(cbl_conn *c, atomic_int *flag, int want)
{
	struct pollfd pfd;
	int events, timeout;

	for (int i = 0; i < 500 && *flag < want; i++) {
		(void)cbl_conn_interest(c, &events, &timeout);
		pfd.fd = cbl_conn_fd(c);
		pfd.events = POLLIN | ((events & CBL_EV_WRITE) ? POLLOUT : 0);
		pfd.revents = 0;
		(void)poll(&pfd, 1, 10);
		(void)cbl_conn_process(c,
		    ((pfd.revents & (POLLIN | POLLHUP)) ? CBL_EV_READ : 0) |
		    ((pfd.revents & POLLOUT) ? CBL_EV_WRITE : 0));
	}
}

ATF_TC_WITHOUT_HEAD(streams_and_events);
ATF_TC_BODY(streams_and_events, tc)
{
	static const struct types_events_handlers h = {
	    .changed = changed_ntf };
	struct types_chat_req chat = { .name = "alice" };
	struct types_feed_req feed = { .has_u16 = true, .u16 = 25 };
	struct types_upload_req up = { .name = "x" };
	struct types_changed_ntf ntf = { .name = "k1", .has_u32 = true,
	    .u32 = TYPES_COLOR_BLUE };
	struct types_point p = { .has_x = true, .x = 21 };
	struct sockaddr_storage ss;
	struct types_client cl;
	cbl_ctx *sctx = ctx_new(), *cctx = ctx_new();
	struct crec r;
	cbl_listener *l;
	cbl_family *fam;
	cbl_stream *s;
	cbl_loop *loop;
	cbl_conn *c;
	cbl_sub *sub;
	pthread_t thr;
	char uri[64];

	ATF_REQUIRE_EQ(0, types_register(sctx, NULL, &fam));
	ATF_REQUIRE_EQ(0, cbl_loop_new(sctx, &loop));
	ATF_REQUIRE_EQ(0, cbl_listener_new(sctx, "tcp://127.0.0.1:0",
	    CBL_PLAINTEXT, &l));
	ATF_REQUIRE_EQ(0, cbl_listener_start(l, loop));
	ATF_REQUIRE_EQ(0, cbl_listener_addr(l, &ss, NULL));
	snprintf(uri, sizeof(uri), "tcp://127.0.0.1:%u",
	    ntohs(((struct sockaddr_in *)&ss)->sin_port));
	ATF_REQUIRE_EQ(0, pthread_create(&thr, NULL, loop_thread, loop));
	ATF_REQUIRE_EQ(0, cbl_conn_new(cctx, uri, CBL_PLAINTEXT, &c));
	ATF_REQUIRE_EQ(0, cbl_conn_connect(c));
	ATF_REQUIRE_EQ(0, types_client_init(&cl, c));

	/* Bidirectional chat: typed accept, typed data both ways. */
	memset(&r, 0, sizeof(r));
	ATF_REQUIRE_EQ(0, types_chat_open(&cl, &chat, &chat_c_cbs, &r, &s));
	pump(c, &r.opened, 1);
	ATF_REQUIRE_EQ(0, r.open_error);
	ATF_REQUIRE_EQ(42, r.accept_u8);
	/* The spec's initial-credit. */
	ATF_REQUIRE_EQ(4096, cbl_stream_credit(s));
	ATF_REQUIRE_EQ(0, types_chat_send(s, &p));
	pump(c, &r.data, 1);
	ATF_REQUIRE_EQ(42, r.last_y);
	ATF_REQUIRE_EQ(0, cbl_stream_half_close(s));
	pump(c, &r.closed, 1);
	ATF_REQUIRE_EQ(1, r.closed);
	/*
	 * A payload that breaks its policy ("x" is required) is not
	 * dropped: the receiver resets the stream.
	 */
	memset(&r, 0, sizeof(r));
	ATF_REQUIRE_EQ(0, types_chat_open(&cl, &chat, &chat_c_cbs, &r, &s));
	pump(c, &r.opened, 1);
	ATF_REQUIRE_EQ(0, types_chat_send(s, &(struct types_point){
	    .has_y = true, .y = 1 }));
	pump(c, &r.closed, 1);
	ATF_REQUIRE_EQ(EBADMSG, r.close_code);
	ATF_REQUIRE_EQ(0, r.data);
	/* A refused open. */
	memset(&r, 0, sizeof(r));
	chat.name = "mallory";
	ATF_REQUIRE_EQ(0, types_chat_open(&cl, &chat, &chat_c_cbs, &r, &s));
	pump(c, &r.closed, 1);
	ATF_REQUIRE_EQ(EACCES, r.open_error);

	/* Push feed: the client only receives. */
	memset(&r, 0, sizeof(r));
	ATF_REQUIRE_EQ(0, types_feed_open(&cl, &feed, &feed_c_cbs, &r, &s));
	pump(c, &r.closed, 1);
	ATF_REQUIRE_EQ(25, r.data);
	ATF_REQUIRE_STREQ("even", r.last);

	/* Upload: the client only sends. */
	memset(&r, 0, sizeof(r));
	ATF_REQUIRE_EQ(0, types_upload_open(&cl, &up, &upload_c_cbs, &r, &s));
	pump(c, &r.opened, 1);
	ATF_REQUIRE_EQ(0, r.open_error);
	/* The default window. */
	ATF_REQUIRE_EQ(256 * 1024, cbl_stream_credit(s));
	for (int i = 0; i < 10; i++)
		ATF_REQUIRE_EQ(0, types_upload_send(s, &p));
	ATF_REQUIRE_EQ(0, cbl_stream_half_close(s));
	pump(c, &r.closed, 1);
	for (int i = 0; i < 200 && upload_closed == 0; i++)
		usleep(5000);
	ATF_REQUIRE_EQ(10, uploaded);

	/* Typed notifications. */
	memset(&r, 0, sizeof(r));
	ATF_REQUIRE_EQ(0, types_events_subscribe(&cl, &h, &r, &sub));
	ATF_REQUIRE_EQ(0, types_changed_notify(fam, &ntf));
	pump(c, &r.ntf, 1);
	ATF_REQUIRE_EQ(1, r.ntf);
	ATF_REQUIRE_STREQ("k1", r.last);
	ATF_REQUIRE_EQ(0, types_events_unsubscribe(sub));

	types_client_fini(&cl);
	cbl_conn_free(c);
	cbl_loop_stop(loop);
	pthread_join(thr, NULL);
	cbl_listener_free(l);
	cbl_loop_free(loop);
	ATF_REQUIRE_EQ(0, cbl_family_unregister(fam));
	cbl_ctx_free(sctx);
	cbl_ctx_free(cctx);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, struct_roundtrip);
	ATF_TP_ADD_TC(tp, builders);
	ATF_TP_ADD_TC(tp, policies);
	ATF_TP_ADD_TC(tp, client_server);
	ATF_TP_ADD_TC(tp, streams_and_events);
	return (atf_no_error());
}
