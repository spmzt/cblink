/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* Multicast notifications and subscriptions. */

#include <stdatomic.h>
#include <time.h>

#include "cbl_net_test.h"

enum { N_PING = 1, N_EVENT };
enum { NA_SEQ = 1, NA_PAD };
enum { G_EVENTS, G_AUDIT };

static int
nping_doit(cbl_req *req __unused, const cbl_msg *msg __unused,
    void *arg __unused)
{

	return (0);
}

static const struct cbl_op n_ops[] = {
	{ .cmd = N_PING, .name = "ping", .flags = CBL_OPF_DO,
	  .doit = nping_doit },
};
static const struct cbl_mcgrp n_grps[] = {
	{ .name = "events" },
	{ .name = "audit", .flags = CBL_MCF_AUTH },
};
static const struct cbl_family_def n_def = {
	.abi = CBL_FAMILY_ABI, .name = "news", .version = 1,
	.ops = n_ops, .nops = nitems(n_ops),
	.mcgrps = n_grps, .nmcgrps = nitems(n_grps),
};

struct rec {
	atomic_int	 n;
	atomic_int	 missed;
	atomic_bool	 in_order;
	atomic_uint	 group;
	uint64_t	 next;
	char		 name[64];
	atomic_int	 kind;
};

static void
rec_cb(cbl_conn *conn __unused, cbl_msg *msg, void *arg)
{
	struct rec *r = arg;
	uint64_t seq = UINT64_MAX;

	r->group = cbl_msg_stream(msg);
	if (cbl_msg_err_code(msg) == ENOBUFS)
		r->missed++;
	(void)cbl_attr_uint(cbl_msg_attr(msg, NA_SEQ), &seq);
	if (seq != r->next)
		r->in_order = false;
	r->next = seq + 1;
	r->n++;
}

/* Server-side connections, captured as they are accepted. */
struct srvconns {
	pthread_mutex_t	 mtx;
	cbl_conn	*c[8];
	int		 n;
};

static void
on_open(cbl_conn *conn, void *arg)
{
	struct srvconns *sc = arg;

	pthread_mutex_lock(&sc->mtx);
	if (sc->n < 8)
		sc->c[sc->n++] = conn;
	pthread_mutex_unlock(&sc->mtx);
}

static void
on_close(cbl_conn *conn, int error __unused, void *arg)
{
	struct srvconns *sc = arg;

	pthread_mutex_lock(&sc->mtx);
	for (int i = 0; i < sc->n; i++)
		if (sc->c[i] == conn)
			sc->c[i] = NULL;
	pthread_mutex_unlock(&sc->mtx);
}

struct fx {
	cbl_ctx			*sctx, *cctx;
	struct test_server	 ts;
	cbl_family		*fam;
	struct srvconns		 sc;
};

struct lim {
	enum cbl_limit	 l;
	uint64_t	 v;
};

/* A server with these limits on its context. */
static void
fx_setup_lim(struct fx *f, const struct lim *lims, size_t nlims)
{
	static const struct cbl_conn_cbs cbs = { on_open, on_close };

	memset(f, 0, sizeof(*f));
	pthread_mutex_init(&f->sc.mtx, NULL);
	f->sctx = test_ctx();
	f->cctx = test_ctx();
	for (size_t i = 0; i < nlims; i++)
		ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(f->sctx, lims[i].l,
		    lims[i].v));
	ATF_REQUIRE_EQ(0, cbl_ctx_set_conn_cbs(f->sctx, &cbs, &f->sc));
	ATF_REQUIRE_EQ(0, cbl_family_register(f->sctx, &n_def, NULL, &f->fam));
	test_server_start(&f->ts, f->sctx, "tcp://127.0.0.1:0", CBL_PLAINTEXT);
}

static void
fx_setup(struct fx *f, uint64_t sendq)
{
	struct lim l = { CBL_LIM_SENDQ_BYTES, sendq };

	fx_setup_lim(f, &l, sendq != 0 ? 1 : 0);
}

/* Server-side connections still open. */
static int
fx_live(struct fx *f)
{
	int n = 0;

	pthread_mutex_lock(&f->sc.mtx);
	for (int i = 0; i < f->sc.n; i++)
		if (f->sc.c[i] != NULL)
			n++;
	pthread_mutex_unlock(&f->sc.mtx);
	return (n);
}

static cbl_conn *
fx_client(struct fx *f)
{
	cbl_conn *c;

	ATF_REQUIRE_EQ(0, cbl_conn_new(f->cctx, f->ts.uri, CBL_PLAINTEXT, &c));
	ATF_REQUIRE_EQ(0, cbl_conn_connect(c));
	return (c);
}

static void
fx_teardown(struct fx *f)
{

	test_server_stop(&f->ts);
	if (f->fam != NULL)
		ATF_REQUIRE_EQ(0, cbl_family_unregister(f->fam));
	cbl_ctx_free(f->sctx);
	cbl_ctx_free(f->cctx);
	pthread_mutex_destroy(&f->sc.mtx);
}

static uint64_t
ms_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000);
}

static void
drive(cbl_conn *c, atomic_int *flag, int want, int ms)
{
	uint64_t end = ms_now() + (uint64_t)ms;
	struct pollfd pfd;
	int events, timeout;

	while ((flag == NULL || *flag < want) && ms_now() < end) {
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

static void
broadcast(struct fx *f, uint16_t cmd, uint32_t gidx, uint64_t first,
    uint64_t n, size_t pad)
{
	static char padbuf[16384];
	cbl_msg *m;

	for (uint64_t i = first; i < first + n; i++) {
		ATF_REQUIRE_EQ(0, cbl_notify_msg_new(f->fam, cmd, &m));
		cbl_put_uint(m, NA_SEQ, i);
		if (pad > 0)
			cbl_put_bytes(m, NA_PAD, padbuf, pad);
		ATF_REQUIRE_EQ(0, cbl_notify(f->fam, gidx, m));
	}
}

ATF_TC_WITHOUT_HEAD(subscribe);
ATF_TC_BODY(subscribe, tc)
{
	struct fx f;
	struct rec r = { .in_order = true };
	cbl_conn *c;
	cbl_sub *sub;

	fx_setup(&f, 0);
	c = fx_client(&f);
	ATF_REQUIRE_EQ(0, cbl_subscribe(c, "news", "events", rec_cb, &r, &sub));
	ATF_REQUIRE(cbl_sub_arg(sub) == &r);
	/* Nobody listens to "audit": no delivery. */
	broadcast(&f, N_EVENT, G_AUDIT, 1000, 5, 0);
	broadcast(&f, N_EVENT, G_EVENTS, 0, 100, 0);
	drive(c, &r.n, 100, 5000);
	ATF_REQUIRE_EQ(100, r.n);
	ATF_REQUIRE(r.in_order);
	ATF_REQUIRE_EQ(cbl_family_group_id(f.fam, G_EVENTS), r.group);
	ATF_REQUIRE_EQ(0, r.missed);
	/* After unsubscribing nothing more arrives. */
	ATF_REQUIRE_EQ(0, cbl_unsubscribe(sub));
	ATF_REQUIRE_EQ(0, cbl_ping(c, 2000));	/* unsubscribe processed */
	broadcast(&f, N_EVENT, G_EVENTS, 100, 10, 0);
	ATF_REQUIRE_EQ(0, cbl_ping(c, 2000));
	drive(c, NULL, 0, 200);
	ATF_REQUIRE_EQ(100, r.n);
	cbl_conn_free(c);
	fx_teardown(&f);
}

ATF_TC_WITHOUT_HEAD(errors);
ATF_TC_BODY(errors, tc)
{
	struct fx f;
	struct rec r;
	cbl_conn *c;
	cbl_sub *sub;

	fx_setup(&f, 0);
	c = fx_client(&f);
	ATF_REQUIRE_EQ(EACCES, cbl_subscribe(c, "news", "audit", rec_cb, &r,
	    &sub));
	ATF_REQUIRE_EQ(ENOENT, cbl_subscribe(c, "news", "nope", rec_cb, &r,
	    &sub));
	ATF_REQUIRE_EQ(ENOENT, cbl_subscribe(c, "nonews", "events", rec_cb,
	    &r, &sub));
	/* A group id that belongs to another family. */
	ATF_REQUIRE_EQ(ENOENT, cbl_subscribe_id(c, cbl_family_id(f.fam),
	    CBL_CTRL_GROUP_NOTIFY, rec_cb, &r, &sub));
	cbl_conn_free(c);
	fx_teardown(&f);
}

ATF_TC_WITHOUT_HEAD(many_subscribers);
ATF_TC_BODY(many_subscribers, tc)
{
	struct fx f;
	struct rec r[3];
	cbl_conn *c[3];
	cbl_sub *sub[3];

	fx_setup(&f, 0);
	for (int i = 0; i < 3; i++) {
		memset(&r[i], 0, sizeof(r[i]));
		r[i].in_order = true;
		c[i] = fx_client(&f);
		ATF_REQUIRE_EQ(0, cbl_subscribe(c[i], "news", "events", rec_cb,
		    &r[i], &sub[i]));
	}
	broadcast(&f, N_EVENT, G_EVENTS, 0, 50, 0);
	for (int i = 0; i < 3; i++) {
		drive(c[i], &r[i].n, 50, 5000);
		ATF_REQUIRE_EQ(50, r[i].n);
		ATF_REQUIRE(r[i].in_order);
	}
	/* A closed subscriber is dropped from the group. */
	cbl_unsubscribe(sub[0]);
	cbl_conn_free(c[0]);
	usleep(100000);
	broadcast(&f, N_EVENT, G_EVENTS, 50, 10, 0);
	for (int i = 1; i < 3; i++) {
		drive(c[i], &r[i].n, 60, 5000);
		ATF_REQUIRE_EQ(60, r[i].n);
		cbl_unsubscribe(sub[i]);
		cbl_conn_free(c[i]);
	}
	fx_teardown(&f);
}

/* ctrl "notify": families coming and going. */
static void
ctrl_cb(cbl_conn *conn __unused, cbl_msg *msg, void *arg)
{
	struct rec *r = arg;
	const char *name;

	r->kind = cbl_msg_cmd(msg);
	if (cbl_attr_str(msg, cbl_msg_attr(msg, 2), &name) == 0)
		strlcpy(r->name, name, sizeof(r->name));
	r->n++;
}

ATF_TC_WITHOUT_HEAD(ctrl_notify);
ATF_TC_BODY(ctrl_notify, tc)
{
	static const struct cbl_family_def other = {
		.abi = CBL_FAMILY_ABI, .name = "latecomer", .version = 1,
		.ops = n_ops, .nops = nitems(n_ops),
	};
	struct fx f;
	struct rec r = {};
	cbl_family *fam;
	cbl_conn *c;
	cbl_sub *sub;

	fx_setup(&f, 0);
	c = fx_client(&f);
	ATF_REQUIRE_EQ(0, cbl_subscribe(c, "ctrl", "notify", ctrl_cb, &r,
	    &sub));
	ATF_REQUIRE_EQ(0, cbl_family_register(f.sctx, &other, NULL, &fam));
	drive(c, &r.n, 1, 3000);
	ATF_REQUIRE_EQ(1, r.n);
	ATF_REQUIRE_EQ(6, r.kind);		/* newfamily */
	ATF_REQUIRE_STREQ("latecomer", r.name);
	ATF_REQUIRE_EQ(0, cbl_family_unregister(fam));
	drive(c, &r.n, 2, 3000);
	ATF_REQUIRE_EQ(2, r.n);
	ATF_REQUIRE_EQ(7, r.kind);		/* delfamily */
	cbl_unsubscribe(sub);
	cbl_conn_free(c);
	fx_teardown(&f);
}

/*
 * A subscriber that does not read: notifications beyond its send queue
 * are dropped, and the next one it gets says so (CODE = ENOBUFS).
 */
ATF_TC_WITHOUT_HEAD(slow_subscriber);
ATF_TC_BODY(slow_subscriber, tc)
{
	struct cbl_conn_stats st;
	cbl_conn *sc;
	struct fx f;
	struct rec r = { .in_order = true };
	cbl_conn *c;
	cbl_sub *sub;

	fx_setup(&f, 64 * 1024);
	c = fx_client(&f);
	ATF_REQUIRE_EQ(0, cbl_subscribe(c, "news", "events", rec_cb, &r, &sub));
	/* 16 MB while the client sleeps: more than socket buffers can hold. */
	broadcast(&f, N_EVENT, G_EVENTS, 0, 2000, 8000);
	drive(c, NULL, 0, 3000);
	ATF_REQUIRE(r.n > 0);
	ATF_REQUIRE(r.n < 2000);	/* some were dropped */
	/* ... and the server's connection counted them. */
	pthread_mutex_lock(&f.sc.mtx);
	sc = f.sc.c[0];
	pthread_mutex_unlock(&f.sc.mtx);
	ATF_REQUIRE_EQ(0, cbl_conn_stats(sc, &st));
	ATF_REQUIRE(st.ntf_dropped > 0);
	ATF_REQUIRE_EQ(0, st.streams);
	ATF_REQUIRE_EQ(0, cbl_conn_stats(c, &st));
	ATF_REQUIRE_EQ(0, st.pending);
	/* Room again: the next delivery carries the warning. */
	broadcast(&f, N_EVENT, G_EVENTS, 1000, 1, 0);
	r.missed = 0;
	drive(c, &r.missed, 1, 3000);
	ATF_REQUIRE_EQ(1, r.missed);
	ATF_REQUIRE(!r.in_order);	/* and the gap is visible */
	cbl_unsubscribe(sub);
	cbl_conn_free(c);
	fx_teardown(&f);
}

ATF_TC_WITHOUT_HEAD(unicast);
ATF_TC_BODY(unicast, tc)
{
	struct fx f;
	struct rec r1 = { .in_order = true }, r2 = { .in_order = true };
	cbl_conn *c1, *c2;
	cbl_sub *s1, *s2;
	cbl_msg *m;

	fx_setup(&f, 0);
	c1 = fx_client(&f);
	c2 = fx_client(&f);
	ATF_REQUIRE_EQ(0, cbl_subscribe(c1, "news", "events", rec_cb, &r1,
	    &s1));
	ATF_REQUIRE_EQ(0, cbl_subscribe(c2, "news", "events", rec_cb, &r2,
	    &s2));
	ATF_REQUIRE_EQ(2, f.sc.n);
	pthread_mutex_lock(&f.sc.mtx);
	ATF_REQUIRE_EQ(0, cbl_notify_msg_new(f.fam, N_EVENT, &m));
	cbl_put_uint(m, NA_SEQ, 0);
	ATF_REQUIRE_EQ(0, cbl_conn_notify(f.sc.c[1], f.fam, G_EVENTS, m));
	pthread_mutex_unlock(&f.sc.mtx);
	drive(c2, &r2.n, 1, 3000);
	drive(c1, NULL, 0, 200);
	ATF_REQUIRE_EQ(1, r1.n + r2.n);
	cbl_unsubscribe(s1);
	cbl_unsubscribe(s2);
	cbl_conn_free(c1);
	cbl_conn_free(c2);
	fx_teardown(&f);
}

/* Unsubscribing from another thread waits for a running callback. */
struct slow {
	atomic_int	 entered;
	atomic_int	 left;
};

static void
slow_cb(cbl_conn *conn __unused, cbl_msg *msg __unused, void *arg)
{
	struct slow *s = arg;

	s->entered++;
	usleep(300000);
	s->left++;
}

static void *
loop_thread(void *arg)
{

	(void)cbl_loop_run(arg);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(unsubscribe_waits);
ATF_TC_BODY(unsubscribe_waits, tc)
{
	struct fx f;
	struct slow s = {};
	cbl_loop *loop;
	pthread_t thr;
	cbl_conn *c;
	cbl_sub *sub;

	fx_setup(&f, 0);
	c = fx_client(&f);
	ATF_REQUIRE_EQ(0, cbl_loop_new(f.cctx, &loop));
	ATF_REQUIRE_EQ(0, cbl_conn_attach(c, loop));
	ATF_REQUIRE_EQ(0, pthread_create(&thr, NULL, loop_thread, loop));
	ATF_REQUIRE_EQ(0, cbl_subscribe(c, "news", "events", slow_cb, &s,
	    &sub));
	broadcast(&f, N_EVENT, G_EVENTS, 0, 1, 0);
	for (int i = 0; i < 200 && s.entered == 0; i++)
		usleep(5000);
	ATF_REQUIRE_EQ(1, s.entered);
	ATF_REQUIRE_EQ(0, cbl_unsubscribe(sub));
	ATF_REQUIRE_EQ(1, s.left);	/* returned only after the callback */
	cbl_loop_stop(loop);
	pthread_join(thr, NULL);
	cbl_conn_free(c);
	cbl_loop_free(loop);
	fx_teardown(&f);
}

/*
 * A thread notifies while subscribers come and go abruptly (RST): kicks
 * queued for a connection that has just died must not touch its loop.
 */
struct notifier {
	cbl_family	*fam;
	atomic_bool	 stop;
};

static void *
notifier_thread(void *arg)
{
	struct notifier *nt = arg;
	cbl_msg *m;

	while (!nt->stop) {
		if (cbl_notify_msg_new(nt->fam, N_EVENT, &m) == 0) {
			cbl_put_uint(m, NA_SEQ, 0);
			(void)cbl_notify(nt->fam, G_EVENTS, m);
		}
	}
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(notify_while_aborting);
ATF_TC_BODY(notify_while_aborting, tc)
{
	struct linger lg = { .l_onoff = 1, .l_linger = 0 };
	struct notifier nt;
	struct fx f;
	pthread_t thr;
	cbl_msg *m;
	uint64_t end;
	int fd;

	fx_setup(&f, 0);
	nt.fam = f.fam;
	nt.stop = false;
	ATF_REQUIRE_EQ(0, pthread_create(&thr, NULL, notifier_thread, &nt));
	end = ms_now() + 3000;
	for (int i = 0; i < 3000 && ms_now() < end; i++) {
		fd = raw_connect(f.ts.uri);
		ATF_REQUIRE_EQ(0, cbl_msg_new(f.cctx, 0, 2, CBL_F_REQUEST |
		    CBL_F_ACK, &m));
		cbl_put_uint(m, 1, cbl_family_id(f.fam));
		cbl_put_uint(m, 6, cbl_family_group_id(f.fam, G_EVENTS));
		raw_send_msg(fd, m);
		/* The ACK, or already a notification: subscribed either way. */
		ATF_REQUIRE((m = raw_read_msg(f.cctx, fd)) != NULL);
		cbl_msg_free(m);
		ATF_REQUIRE_EQ(0, setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg,
		    sizeof(lg)));
		close(fd);
	}
	nt.stop = true;
	pthread_join(thr, NULL);
	fx_teardown(&f);
}

/*
 * Notifications sent from a loop timer to a subscriber that only starts
 * reading later: the send queue must drain once the socket has room,
 * although the subscriber's connection had no event of its own.
 */
#define	BIG_N		40
#define	BIG_PAD		(500 * 1024)

static void
big_fanout(cbl_timer *t __unused, void *arg)
{
	static char pad[BIG_PAD];
	cbl_family *fam = arg;
	cbl_msg *m;

	for (uint64_t i = 0; i < BIG_N; i++) {
		if (cbl_notify_msg_new(fam, N_EVENT, &m) != 0)
			return;
		cbl_put_uint(m, NA_SEQ, i);
		cbl_put_bytes(m, NA_PAD, pad, sizeof(pad));
		(void)cbl_notify(fam, G_EVENTS, m);
	}
}

/* Timers belong to the loop thread: start this one from there. */
struct fanout_start {
	cbl_loop	*loop;
	cbl_family	*fam;
};

static void
fanout_start(void *arg)
{
	struct fanout_start *fs = arg;

	(void)cbl_loop_timer(fs->loop, 100, 0, big_fanout, fs->fam, NULL);
}

ATF_TC_WITHOUT_HEAD(timer_fanout_late_reader);
ATF_TC_BODY(timer_fanout_late_reader, tc)
{
	struct fanout_start fs;
	struct rec r = { .in_order = true };
	struct fx f;
	cbl_conn *c;
	cbl_sub *sub;

	fx_setup(&f, 64 * 1024 * 1024);
	c = fx_client(&f);
	ATF_REQUIRE_EQ(0, cbl_subscribe(c, "news", "events", rec_cb, &r, &sub));
	fs.loop = f.ts.loop;
	fs.fam = f.fam;
	ATF_REQUIRE_EQ(0, cbl_loop_post(f.ts.loop, fanout_start, &fs));
	usleep(2000000);	/* the server fills the socket and waits */
	drive(c, &r.n, BIG_N, 15000);
	ATF_REQUIRE_EQ(BIG_N, r.n);
	ATF_REQUIRE(r.in_order);
	cbl_unsubscribe(sub);
	cbl_conn_free(c);
	fx_teardown(&f);
}

/*
 * idle_timeout on both ends, and a group that stays quiet: the healthy
 * connection survives on keepalives, and still delivers afterwards.
 */
ATF_TC_WITHOUT_HEAD(quiet_subscriber);
ATF_TC_BODY(quiet_subscriber, tc)
{
	static const struct lim lims[] = { { CBL_LIM_IDLE_MS, 300 } };
	struct rec r = { .in_order = true };
	struct fx f;
	cbl_conn *c;
	cbl_sub *sub;

	fx_setup_lim(&f, lims, nitems(lims));
	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(f.cctx, CBL_LIM_IDLE_MS, 300));
	c = fx_client(&f);
	ATF_REQUIRE_EQ(0, cbl_subscribe(c, "news", "events", rec_cb, &r, &sub));
	drive(c, NULL, 0, 1500);
	ATF_REQUIRE_MSG(cbl_conn_is_open(c), "%s", cbl_conn_errstr(c));
	ATF_REQUIRE_EQ(1, fx_live(&f));
	broadcast(&f, N_EVENT, G_EVENTS, 0, 1, 0);
	drive(c, &r.n, 1, 3000);
	ATF_REQUIRE_EQ(1, r.n);
	cbl_unsubscribe(sub);
	cbl_conn_free(c);
	fx_teardown(&f);
}

/*
 * The server closes a connection whose peer has stopped reading, with
 * output still queued: the close gives up after close_timeout.
 */
ATF_TC_WITHOUT_HEAD(close_while_peer_stalls);
ATF_TC_BODY(close_while_peer_stalls, tc)
{
	static const struct lim lims[] = {
		{ CBL_LIM_SENDQ_BYTES, 64 * 1024 * 1024 },
		{ CBL_LIM_STREAM_CLOSE_MS, 300 },
	};
	struct rec r = { .in_order = true };
	struct fx f;
	cbl_conn *c, *sc;
	cbl_sub *sub;

	fx_setup_lim(&f, lims, nitems(lims));
	c = fx_client(&f);
	ATF_REQUIRE_EQ(0, cbl_subscribe(c, "news", "events", rec_cb, &r, &sub));
	ATF_REQUIRE_EQ(1, fx_live(&f));
	/* 8 MB the client never reads. */
	broadcast(&f, N_EVENT, G_EVENTS, 0, 1000, 8000);
	pthread_mutex_lock(&f.sc.mtx);
	sc = f.sc.c[0];
	pthread_mutex_unlock(&f.sc.mtx);
	ATF_REQUIRE_EQ(0, cbl_conn_close(sc));
	for (int i = 0; i < 300 && fx_live(&f) > 0; i++)
		usleep(10000);
	ATF_REQUIRE_EQ(0, fx_live(&f));
	cbl_unsubscribe(sub);
	cbl_conn_free(c);
	fx_teardown(&f);
}

/*
 * A client on a loop resolves and subscribes from the loop thread, where
 * the synchronous calls would give EDEADLK.
 */
struct async_sub {
	cbl_conn	*c;
	struct rec	*r;
	atomic_int	 resolved;
	atomic_int	 subscribed;
	atomic_int	 error;
	cbl_sub		*sub;
	uint16_t	 fid;
};

static void
async_resolved(cbl_conn *conn __unused, int error, cbl_family_info *info,
    void *arg)
{
	struct async_sub *as = arg;

	if (error == 0)
		as->fid = cbl_family_info_id(info);
	cbl_family_info_free(info);
	as->error = error;
	as->resolved++;
}

static void
async_subscribed(cbl_conn *conn __unused, int error, cbl_sub *sub, void *arg)
{
	struct async_sub *as = arg;

	as->sub = sub;
	as->error = error;
	as->subscribed++;
}

static void
async_start(void *arg)
{
	struct async_sub *as = arg;

	ATF_REQUIRE_EQ(EDEADLK, cbl_subscribe(as->c, "news", "events", rec_cb,
	    as->r, &as->sub));
	ATF_REQUIRE_EQ(0, cbl_resolve_async(as->c, "news", async_resolved,
	    as));
	ATF_REQUIRE_EQ(0, cbl_subscribe_async(as->c, "news", "events", rec_cb,
	    as->r, async_subscribed, as));
}

ATF_TC_WITHOUT_HEAD(async_subscribe);
ATF_TC_BODY(async_subscribe, tc)
{
	struct rec r = { .in_order = true };
	struct async_sub as;
	struct test_server cl;
	struct fx f;

	fx_setup(&f, 0);
	memset(&as, 0, sizeof(as));
	as.r = &r;
	as.c = fx_client(&f);
	memset(&cl, 0, sizeof(cl));
	ATF_REQUIRE_EQ(0, cbl_loop_new(f.cctx, &cl.loop));
	ATF_REQUIRE_EQ(0, cbl_conn_attach(as.c, cl.loop));
	ATF_REQUIRE_EQ(0, pthread_create(&cl.thr, NULL, test_server_thread,
	    &cl));
	ATF_REQUIRE_EQ(0, cbl_loop_post(cl.loop, async_start, &as));
	for (int i = 0; i < 300 && as.subscribed == 0; i++)
		usleep(10000);
	ATF_REQUIRE_EQ(1, as.resolved);
	ATF_REQUIRE_EQ(cbl_family_id(f.fam), as.fid);
	ATF_REQUIRE_EQ(1, as.subscribed);
	ATF_REQUIRE_EQ(0, as.error);
	ATF_REQUIRE(as.sub != NULL);
	broadcast(&f, N_EVENT, G_EVENTS, 0, 1, 0);
	for (int i = 0; i < 300 && r.n == 0; i++)
		usleep(10000);
	ATF_REQUIRE_EQ(1, r.n);
	cbl_conn_free(as.c);
	cbl_loop_stop(cl.loop);
	pthread_join(cl.thr, NULL);
	cbl_loop_free(cl.loop);
	fx_teardown(&f);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, subscribe);
	ATF_TP_ADD_TC(tp, errors);
	ATF_TP_ADD_TC(tp, many_subscribers);
	ATF_TP_ADD_TC(tp, ctrl_notify);
	ATF_TP_ADD_TC(tp, slow_subscriber);
	ATF_TP_ADD_TC(tp, unicast);
	ATF_TP_ADD_TC(tp, unsubscribe_waits);
	ATF_TP_ADD_TC(tp, notify_while_aborting);
	ATF_TP_ADD_TC(tp, timer_fanout_late_reader);
	ATF_TP_ADD_TC(tp, quiet_subscriber);
	ATF_TP_ADD_TC(tp, close_while_peer_stalls);
	ATF_TP_ADD_TC(tp, async_subscribe);
	return (atf_no_error());
}
