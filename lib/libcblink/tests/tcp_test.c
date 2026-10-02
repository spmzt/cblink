/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* TCP transport and connection core. */

#include <sys/resource.h>

#include <fcntl.h>
#include <netdb.h>
#include <signal.h>

#include <stdatomic.h>
#include <time.h>

#include "cbl_net_test.h"

static cbl_conn *
client_connect(cbl_ctx *ctx, const char *uri)
{
	cbl_conn *conn;
	int error;

	ATF_REQUIRE_EQ(0, cbl_conn_new(ctx, uri, CBL_PLAINTEXT, &conn));
	error = cbl_conn_connect(conn);
	ATF_REQUIRE_MSG(error == 0, "connect: %s", cbl_conn_errstr(conn));
	return (conn);
}

ATF_TC_WITHOUT_HEAD(plaintext_opt_in);
ATF_TC_BODY(plaintext_opt_in, tc)
{
	cbl_ctx *ctx = test_ctx();
	cbl_listener *l;
	cbl_conn *c;

	/* Without TLS and without CBL_PLAINTEXT, nothing connects. */
	ATF_REQUIRE_EQ(0, cbl_conn_new(ctx, "tcp://127.0.0.1:1", 0, &c));
	ATF_REQUIRE_EQ(EPERM, cbl_conn_connect(c));
	ATF_REQUIRE_MATCH("mTLS required", cbl_conn_errstr(c));
	cbl_conn_free(c);
	ATF_REQUIRE_EQ(0, cbl_listener_new(ctx, "tcp://127.0.0.1:0", 0, &l));
	ATF_REQUIRE_EQ(EPERM, cbl_listener_start(l, NULL));
	ATF_REQUIRE_MATCH("mTLS required", cbl_listener_errstr(l));
	cbl_listener_free(l);
	ATF_REQUIRE_EQ(EINVAL, cbl_conn_new(ctx, "http://x:1", CBL_PLAINTEXT,
	    &c));
	ATF_REQUIRE_EQ(EINVAL, cbl_conn_new(ctx, "tcp://::1:5", CBL_PLAINTEXT,
	    &c));
	ATF_REQUIRE_EQ(EINVAL, cbl_conn_new(ctx, "tcp://h:99999",
	    CBL_PLAINTEXT, &c));
	ATF_REQUIRE_EQ(EINVAL, cbl_conn_new(ctx, "tcp://a,b:1", CBL_PLAINTEXT,
	    &c));
	ATF_REQUIRE_EQ(0, cbl_conn_new(ctx, "tcp://[::1]:5", CBL_PLAINTEXT,
	    &c));
	cbl_conn_free(c);
	cbl_ctx_free(ctx);
}

ATF_TC_WITHOUT_HEAD(connect_refused);
ATF_TC_BODY(connect_refused, tc)
{
	cbl_ctx *ctx = test_ctx();
	uint16_t port;
	char uri[64];
	cbl_conn *c;
	int fd;

	/* Grab a free port, then close it. */
	fd = raw_listen(&port);
	close(fd);
	snprintf(uri, sizeof(uri), "tcp://127.0.0.1:%u", port);
	ATF_REQUIRE_EQ(0, cbl_conn_new(ctx, uri, CBL_PLAINTEXT, &c));
	ATF_REQUIRE_EQ(ECONNREFUSED, cbl_conn_connect(c));
	ATF_REQUIRE(cbl_conn_errstr(c) != NULL);
	cbl_conn_free(c);
	cbl_ctx_free(ctx);
}

/* A request for an unknown family: ERROR with extended ack. */
ATF_TC_WITHOUT_HEAD(unknown_family);
ATF_TC_BODY(unknown_family, tc)
{
	cbl_ctx *ctx = test_ctx();
	struct test_server ts;
	cbl_msg *req, *rsp;
	cbl_conn *c;

	test_server_start(&ts, test_ctx(), "tcp://127.0.0.1:0", CBL_PLAINTEXT);
	c = client_connect(ctx, ts.uri);
	for (int i = 0; i < 100; i++) {
		ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 999, 1, 0, &req));
		cbl_put_str(req, 1, "hello");
		ATF_REQUIRE_EQ(ENOENT, cbl_request(c, req, &rsp, 2000));
		ATF_REQUIRE(rsp != NULL);
		ATF_REQUIRE_STREQ("unknown family 999", cbl_msg_err_str(rsp));
		ATF_REQUIRE_EQ(999, cbl_msg_family(rsp));
		cbl_msg_free(rsp);
	}
	cbl_conn_free(c);
	test_server_stop(&ts);
	cbl_ctx_free(ts.ctx);
	cbl_ctx_free(ctx);
}

struct async_rec {
	int		calls;
	int		finals;
	uint64_t	val;
	int		error;
};

static void
async_cb(cbl_conn *conn, cbl_msg *rsp, bool final, int error,
    void *arg)
{
	struct async_rec *r = arg;

	(void)conn;
	r->calls++;
	if (final) {
		r->finals++;
		r->error = error;
	} else if (rsp != NULL)
		(void)cbl_attr_uint(cbl_msg_attr(rsp, 1), &r->val);
}

/* Replies arriving in reverse order are matched by sequence number. */
ATF_TC_WITHOUT_HEAD(out_of_order);
ATF_TC_BODY(out_of_order, tc)
{
	cbl_ctx *ctx = test_ctx();
	struct async_rec rec[5] = {};
	uint32_t seqs[5];
	cbl_msg *req, *m;
	char uri[64];
	uint16_t port;
	int lfd, fd, events, timeout;
	cbl_conn *c;

	lfd = raw_listen(&port);
	snprintf(uri, sizeof(uri), "tcp://127.0.0.1:%u", port);
	c = client_connect(ctx, uri);
	fd = accept(lfd, NULL, NULL);
	ATF_REQUIRE(fd != -1);

	for (int i = 0; i < 5; i++) {
		ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 7, 1, 0, &req));
		cbl_put_uint(req, 1, (uint64_t)i);
		ATF_REQUIRE_EQ(0, cbl_request_async(c, req, async_cb, &rec[i]));
	}
	for (int i = 0; i < 5; i++) {
		m = raw_read_msg(ctx, fd);
		ATF_REQUIRE(m != NULL);
		ATF_REQUIRE_EQ(CBL_F_REQUEST | CBL_F_ACK, cbl_msg_flags(m));
		seqs[i] = cbl_msg_seq(m);
		cbl_msg_free(m);
	}
	/* Reply in reverse; request 2 fails. */
	for (int i = 4; i >= 0; i--) {
		if (i == 2) {
			ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 7, 1, CBL_F_ERROR,
			    &m));
			cbl_msg_set_seq(m, seqs[i]);
			cbl_msg_put_error(m, EACCES, "nope", NULL, 0, -1);
			raw_send_msg(fd, m);
			continue;
		}
		ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 7, 1, 0, &m));
		cbl_msg_set_seq(m, seqs[i]);
		cbl_put_uint(m, 1, 100 + (uint64_t)i);
		raw_send_msg(fd, m);
		ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 7, 1, CBL_F_ACK, &m));
		cbl_msg_set_seq(m, seqs[i]);
		raw_send_msg(fd, m);
	}
	/* Integration mode: drive the connection by hand. */
	for (int n = 0; n < 200 && rec[0].finals == 0; n++) {
		struct pollfd pfd;

		ATF_REQUIRE_EQ(0, cbl_conn_interest(c, &events, &timeout));
		pfd.fd = cbl_conn_fd(c);
		pfd.events = POLLIN;
		ATF_REQUIRE(poll(&pfd, 1, 100) >= 0);
		ATF_REQUIRE_EQ(0, cbl_conn_process(c,
		    pfd.revents != 0 ? CBL_EV_READ : 0));
	}
	for (int i = 0; i < 5; i++) {
		ATF_REQUIRE_EQ(1, rec[i].finals);
		if (i == 2) {
			ATF_REQUIRE_EQ(EACCES, rec[i].error);
			ATF_REQUIRE_EQ(1, rec[i].calls);
		} else {
			ATF_REQUIRE_EQ(0, rec[i].error);
			ATF_REQUIRE_EQ(100 + (uint64_t)i, rec[i].val);
			ATF_REQUIRE_EQ(2, rec[i].calls);
		}
	}
	close(fd);
	close(lfd);
	cbl_conn_free(c);
	cbl_ctx_free(ctx);
}

/* State shared with a raw peer thread. */
struct peer {
	cbl_ctx		*ctx;
	int		 lfd;
	int		 mode;
	size_t		 big;
};

enum { PEER_TRICKLE, PEER_BIG, PEER_SILENT };

static void *
peer_thread(void *arg)
{
	struct peer *p = arg;
	const void *f;
	cbl_msg *req, *m;
	size_t len;
	char *blob;
	int fd;

	fd = accept(p->lfd, NULL, NULL);
	req = raw_read_msg(p->ctx, fd);
	if (p->mode == PEER_SILENT) {
		/* Never answer; wait for the client to give up. */
		(void)raw_eof(fd, 5000);
		cbl_msg_free(req);
		close(fd);
		return (NULL);
	}
	cbl_msg_new(p->ctx, cbl_msg_family(req), 1, 0, &m);
	cbl_msg_set_seq(m, cbl_msg_seq(req));
	if (p->mode == PEER_BIG) {
		blob = malloc(p->big);
		memset(blob, 0xa5, p->big);
		cbl_put_bytes(m, 1, blob, p->big);
		free(blob);
	} else
		cbl_put_str(m, 1, "trickled");
	cbl_msg_encode(m, &f, &len);
	if (p->mode == PEER_TRICKLE) {
		/* One byte at a time. */
		for (size_t i = 0; i < len; i++) {
			raw_write(fd, (const char *)f + i, 1);
			usleep(200);
		}
	} else
		raw_write(fd, f, len);
	cbl_msg_free(m);
	cbl_msg_new(p->ctx, cbl_msg_family(req), 1, CBL_F_ACK, &m);
	cbl_msg_set_seq(m, cbl_msg_seq(req));
	raw_send_msg(fd, m);
	cbl_msg_free(req);
	(void)raw_eof(fd, 5000);
	close(fd);
	return (NULL);
}

static void
run_peer(int mode, size_t big, int timeout, int want_error)
{
	cbl_ctx *ctx = test_ctx();
	struct peer p = { .ctx = ctx, .mode = mode, .big = big };
	pthread_t thr;
	cbl_msg *req, *rsp;
	const void *data;
	const char *s;
	char uri[64];
	uint16_t port;
	size_t len;
	cbl_conn *c;

	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(ctx, CBL_LIM_MAX_FRAME,
	    4 * 1024 * 1024));
	p.lfd = raw_listen(&port);
	snprintf(uri, sizeof(uri), "tcp://127.0.0.1:%u", port);
	ATF_REQUIRE_EQ(0, pthread_create(&thr, NULL, peer_thread, &p));
	c = client_connect(ctx, uri);
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 3, 1, 0, &req));
	ATF_REQUIRE_EQ(want_error, cbl_request(c, req, &rsp, timeout));
	if (want_error == 0) {
		ATF_REQUIRE(rsp != NULL);
		if (mode == PEER_BIG) {
			ATF_REQUIRE_EQ(0, cbl_attr_bytes(cbl_msg_attr(rsp, 1),
			    &data, &len));
			ATF_REQUIRE_EQ(big, len);
			ATF_REQUIRE_EQ(0xa5, ((const uint8_t *)data)[len - 1]);
		} else {
			ATF_REQUIRE_EQ(0,
			    cbl_attr_str(rsp, cbl_msg_attr(rsp, 1), &s));
			ATF_REQUIRE_STREQ("trickled", s);
		}
		cbl_msg_free(rsp);
	}
	cbl_conn_free(c);
	pthread_join(thr, NULL);
	close(p.lfd);
	cbl_ctx_free(ctx);
}

ATF_TC_WITHOUT_HEAD(fragmented_reply);
ATF_TC_BODY(fragmented_reply, tc)
{

	run_peer(PEER_TRICKLE, 0, 5000, 0);
}

/* Frames larger than the 64 KiB receive ring. */
ATF_TC_WITHOUT_HEAD(big_reply);
ATF_TC_BODY(big_reply, tc)
{

	run_peer(PEER_BIG, 65536 - 30, 5000, 0);
	run_peer(PEER_BIG, 3 * 1024 * 1024, 5000, 0);
}

ATF_TC_WITHOUT_HEAD(request_timeout);
ATF_TC_BODY(request_timeout, tc)
{

	run_peer(PEER_SILENT, 0, 300, ETIMEDOUT);
}

/* Server side: an oversized frame gets EMSGSIZE, then the close. */
ATF_TC_WITHOUT_HEAD(server_oversize);
ATF_TC_BODY(server_oversize, tc)
{
	struct test_server ts;
	unsigned char buf[64];
	cbl_ctx *ctx = test_ctx();
	cbl_msg *m;
	size_t len;
	int fd;

	test_server_start(&ts, test_ctx(), "tcp://127.0.0.1:0", CBL_PLAINTEXT);
	fd = raw_connect(ts.uri);
	len = mkframe(buf, sizeof(buf), 4, 2, CBL_F_REQUEST, 77, 0, "A0");
	buf[4] = 0x01;			/* length = 16 MiB + 25 */
	raw_write(fd, buf, len);
	m = raw_read_msg(ctx, fd);
	ATF_REQUIRE(m != NULL);
	ATF_REQUIRE_EQ(EMSGSIZE, cbl_msg_err_code(m));
	ATF_REQUIRE_EQ(77, cbl_msg_seq(m));
	ATF_REQUIRE_EQ(4, cbl_msg_family(m));
	cbl_msg_free(m);
	ATF_REQUIRE(raw_eof(fd, 2000));
	close(fd);
	test_server_stop(&ts);
	cbl_ctx_free(ts.ctx);
	cbl_ctx_free(ctx);
}

/* Bad magic: the server hangs up without answering. */
ATF_TC_WITHOUT_HEAD(server_bad_magic);
ATF_TC_BODY(server_bad_magic, tc)
{
	struct test_server ts;
	int fd;

	test_server_start(&ts, test_ctx(), "tcp://127.0.0.1:0", CBL_PLAINTEXT);
	fd = raw_connect(ts.uri);
	raw_write(fd, "GET / HTTP/1.1\r\nHost: x\r\n\r\n", 27);
	ATF_REQUIRE(raw_eof(fd, 2000));
	close(fd);
	test_server_stop(&ts);
	cbl_ctx_free(ts.ctx);
}

/*
 * Invalid flags and malformed bodies are answered, and the connection
 * keeps working afterwards.
 */
ATF_TC_WITHOUT_HEAD(server_recovers);
ATF_TC_BODY(server_recovers, tc)
{
	struct test_server ts;
	cbl_ctx *ctx = test_ctx();
	unsigned char buf[128];
	cbl_msg *m;
	size_t len;
	int fd;

	test_server_start(&ts, test_ctx(), "tcp://127.0.0.1:0", CBL_PLAINTEXT);
	fd = raw_connect(ts.uri);

	len = mkframe(buf, sizeof(buf), 4, 2, CBL_F_REQUEST | CBL_F_MULTI, 1,
	    0, "A1 01 63 66 6F 6F");
	raw_write(fd, buf, len);
	m = raw_read_msg(ctx, fd);
	ATF_REQUIRE_EQ(EINVAL, cbl_msg_err_code(m));
	cbl_msg_free(m);

	len = mkframe(buf, sizeof(buf), 4, 2, CBL_F_REQUEST, 2, 0, "A1 01 BF");
	raw_write(fd, buf, len);
	m = raw_read_msg(ctx, fd);
	ATF_REQUIRE_EQ(EPROTO, cbl_msg_err_code(m));
	ATF_REQUIRE(cbl_msg_err_str(m) != NULL);
	ATF_REQUIRE_EQ(2, cbl_msg_seq(m));
	cbl_msg_free(m);

	len = mkframe(buf, sizeof(buf), 4, 2, CBL_F_REQUEST, 3, 0, "A0");
	raw_write(fd, buf, len);
	m = raw_read_msg(ctx, fd);
	ATF_REQUIRE_EQ(ENOENT, cbl_msg_err_code(m));
	ATF_REQUIRE_EQ(3, cbl_msg_seq(m));
	cbl_msg_free(m);

	/* Responses to nothing are dropped silently. */
	len = mkframe(buf, sizeof(buf), 4, 2, 0, 99, 0, "A0");
	raw_write(fd, buf, len);
	len = mkframe(buf, sizeof(buf), 4, 2, CBL_F_REQUEST, 4, 0, NULL);
	raw_write(fd, buf, len);
	m = raw_read_msg(ctx, fd);
	ATF_REQUIRE_EQ(4, cbl_msg_seq(m));
	cbl_msg_free(m);
	close(fd);
	test_server_stop(&ts);
	cbl_ctx_free(ts.ctx);
	cbl_ctx_free(ctx);
}

/* A peer that never sends a frame is dropped after handshake_timeout. */
ATF_TC_WITHOUT_HEAD(first_frame_timeout);
ATF_TC_BODY(first_frame_timeout, tc)
{
	struct test_server ts;
	cbl_ctx *sctx = test_ctx();
	int fd;

	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(sctx, CBL_LIM_HANDSHAKE_MS, 200));
	test_server_start(&ts, sctx, "tcp://127.0.0.1:0", CBL_PLAINTEXT);
	fd = raw_connect(ts.uri);
	ATF_REQUIRE(raw_eof(fd, 3000));
	close(fd);
	test_server_stop(&ts);
	cbl_ctx_free(sctx);
}

ATF_TC_WITHOUT_HEAD(idle_timeout);
ATF_TC_BODY(idle_timeout, tc)
{
	struct test_server ts;
	cbl_ctx *sctx = test_ctx();
	unsigned char buf[64];
	cbl_msg *m;
	size_t len;
	int fd;

	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(sctx, CBL_LIM_IDLE_MS, 300));
	test_server_start(&ts, sctx, "tcp://127.0.0.1:0", CBL_PLAINTEXT);
	fd = raw_connect(ts.uri);
	len = mkframe(buf, sizeof(buf), 4, 2, CBL_F_REQUEST, 1, 0, NULL);
	raw_write(fd, buf, len);
	m = raw_read_msg(sctx, fd);
	cbl_msg_free(m);
	/* A peer that does not answer the keepalive is dropped. */
	ATF_REQUIRE(raw_closed(fd, 3000));
	close(fd);
	test_server_stop(&ts);
	cbl_ctx_free(sctx);
}

/* A client attached to a loop in another thread; sync calls wait. */
struct client_loop {
	cbl_ctx		*ctx;
	cbl_loop	*loop;
	cbl_conn	*conn;
	atomic_int	 deadlk;
};

static void
deadlock_probe(void *arg)
{
	struct client_loop *cl = arg;
	cbl_msg *req;

	cbl_msg_new(cl->ctx, 1, 1, 0, &req);
	cl->deadlk = cbl_request(cl->conn, req, NULL, 100);
}

static void *
loop_thread(void *arg)
{

	(void)cbl_loop_run(arg);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(loop_client);
ATF_TC_BODY(loop_client, tc)
{
	struct test_server ts;
	cbl_ctx *ctx = test_ctx();
	struct client_loop cl = {};
	pthread_t thr;
	cbl_msg *req, *rsp;
	cbl_conn *c;

	test_server_start(&ts, test_ctx(), "tcp://127.0.0.1:0", CBL_PLAINTEXT);
	c = client_connect(ctx, ts.uri);
	ATF_REQUIRE_EQ(0, cbl_loop_new(ctx, &cl.loop));
	ATF_REQUIRE_EQ(0, cbl_conn_attach(c, cl.loop));
	ATF_REQUIRE_EQ(0, pthread_create(&thr, NULL, loop_thread, cl.loop));
	for (int i = 0; i < 50; i++) {
		ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 1234, 1, 0, &req));
		ATF_REQUIRE_EQ(ENOENT, cbl_request(c, req, &rsp, 2000));
		cbl_msg_free(rsp);
	}
	/* A synchronous call on the loop thread itself would deadlock. */
	cl.ctx = ctx;
	cl.conn = c;
	cl.deadlk = -1;
	ATF_REQUIRE_EQ(0, cbl_loop_post(cl.loop, deadlock_probe, &cl));
	for (int i = 0; i < 200 && cl.deadlk == -1; i++)
		usleep(10000);
	ATF_REQUIRE_EQ(EDEADLK, cl.deadlk);
	cbl_loop_stop(cl.loop);
	pthread_join(thr, NULL);
	cbl_conn_free(c);
	cbl_loop_free(cl.loop);
	test_server_stop(&ts);
	cbl_ctx_free(ts.ctx);
	cbl_ctx_free(ctx);
}

/* After ctrl hello, a frame the peer would refuse is refused locally. */
ATF_TC_WITHOUT_HEAD(hello_limits);
ATF_TC_BODY(hello_limits, tc)
{
	static unsigned char big[8192];
	struct test_server ts;
	cbl_ctx *sctx = test_ctx(), *ctx = test_ctx();
	cbl_msg *req, *rsp = NULL;
	cbl_conn *c;

	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(sctx, CBL_LIM_MAX_FRAME, 4096));
	test_server_start(&ts, sctx, "tcp://127.0.0.1:0", CBL_PLAINTEXT);
	c = client_connect(ctx, ts.uri);
	ATF_REQUIRE_EQ(0, cbl_hello(c));
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, CBL_CTRL_FAMILY, 4, 0, &req));
	ATF_REQUIRE_EQ(0, cbl_put_bytes(req, 9, big, sizeof(big)));
	ATF_REQUIRE_EQ(EMSGSIZE, cbl_request(c, req, &rsp, 2000));
	ATF_REQUIRE(rsp == NULL);
	/* Nothing was sent: the connection is fine. */
	ATF_REQUIRE_EQ(0, cbl_ping(c, 2000));
	cbl_conn_free(c);
	test_server_stop(&ts);
	cbl_ctx_free(sctx);
	cbl_ctx_free(ctx);
}

/*
 * A CBL_CF_NONBLOCK client that connects and then stays quiet: the
 * handshake deadline ends when the connection opens, not at its first
 * received frame.
 */
ATF_TC_WITHOUT_HEAD(nonblock_idle);
ATF_TC_BODY(nonblock_idle, tc)
{
	struct test_server ts;
	cbl_ctx *sctx = test_ctx(), *cctx = test_ctx();
	struct pollfd pfd;
	struct timespec t0, t;
	cbl_conn *c;
	int events, timeout, error;
	long ms;

	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(cctx, CBL_LIM_HANDSHAKE_MS, 300));
	test_server_start(&ts, sctx, "tcp://127.0.0.1:0", CBL_PLAINTEXT);
	ATF_REQUIRE_EQ(0, cbl_conn_new(cctx, ts.uri,
	    CBL_PLAINTEXT | CBL_CF_NONBLOCK, &c));
	error = cbl_conn_connect(c);
	ATF_REQUIRE_MSG(error == 0 || error == EINPROGRESS, "connect: %d",
	    error);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	do {
		ATF_REQUIRE_EQ(0, cbl_conn_interest(c, &events, &timeout));
		pfd.fd = cbl_conn_fd(c);
		pfd.events = ((events & CBL_EV_READ) != 0 ? POLLIN : 0) |
		    ((events & CBL_EV_WRITE) != 0 ? POLLOUT : 0);
		pfd.revents = 0;
		(void)poll(&pfd, 1,
		    timeout >= 0 && timeout < 50 ? timeout : 50);
		error = cbl_conn_process(c,
		    ((pfd.revents & (POLLIN | POLLHUP)) != 0 ?
		    CBL_EV_READ : 0) |
		    ((pfd.revents & POLLOUT) != 0 ? CBL_EV_WRITE : 0));
		ATF_REQUIRE_MSG(error == 0, "%s", cbl_conn_errstr(c));
		clock_gettime(CLOCK_MONOTONIC, &t);
		ms = (t.tv_sec - t0.tv_sec) * 1000 +
		    (t.tv_nsec - t0.tv_nsec) / 1000000;
	} while (ms < 1000);
	ATF_REQUIRE(cbl_conn_is_open(c));
	cbl_conn_free(c);
	test_server_stop(&ts);
	cbl_ctx_free(sctx);
	cbl_ctx_free(cctx);
}

/* Can a plain TCP socket connect to "sa"?  -1 when the family is missing. */
static int
try_connect(const struct sockaddr *sa, socklen_t len)
{
	int fd, ok;

	if ((fd = socket(sa->sa_family, SOCK_STREAM, 0)) == -1)
		return (-1);
	ok = connect(fd, sa, len) == 0;
	if (!ok && errno == EADDRNOTAVAIL)
		ok = -1;
	close(fd);
	return (ok);
}

/* "*" listens on IPv4 and IPv6 alike. */
ATF_TC_WITHOUT_HEAD(wildcard_both_families);
ATF_TC_BODY(wildcard_both_families, tc)
{
	struct sockaddr_in sin = { .sin_len = sizeof(sin),
	    .sin_family = AF_INET };
	struct sockaddr_in6 sin6 = { .sin6_len = sizeof(sin6),
	    .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT };
	struct sockaddr_storage ss;
	cbl_ctx *ctx = test_ctx();
	cbl_listener *l;
	cbl_loop *loop;
	in_port_t port;
	int v6;

	ATF_REQUIRE_EQ(0, cbl_loop_new(ctx, &loop));
	ATF_REQUIRE_EQ(0, cbl_listener_new(ctx, "tcp://*:0", CBL_PLAINTEXT,
	    &l));
	ATF_REQUIRE_EQ(0, cbl_listener_start(l, loop));
	ATF_REQUIRE_EQ(0, cbl_listener_addr(l, &ss, NULL));
	port = ss.ss_family == AF_INET6 ?
	    ((struct sockaddr_in6 *)&ss)->sin6_port :
	    ((struct sockaddr_in *)&ss)->sin_port;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = sin6.sin6_port = port;
	ATF_REQUIRE_EQ(1, try_connect((struct sockaddr *)&sin, sizeof(sin)));
	v6 = try_connect((struct sockaddr *)&sin6, sizeof(sin6));
	cbl_listener_free(l);
	cbl_loop_free(loop);
	cbl_ctx_free(ctx);
	if (v6 == -1)
		atf_tc_skip("no ::1 on this host");
	ATF_REQUIRE_EQ(1, v6);
}

/*
 * accept(2) failing for lack of descriptors must not spin the loop: the
 * listener pauses and retries.  Once descriptors are back, the waiting
 * connection is served.
 */
ATF_TC_WITHOUT_HEAD(accept_emfile);
ATF_TC_BODY(accept_emfile, tc)
{
	struct test_server ts;
	cbl_ctx *sctx = test_ctx();
	struct sockaddr_in sin = { .sin_len = sizeof(sin),
	    .sin_family = AF_INET };
	struct rlimit old, low;
	struct timespec a, b;
	unsigned char buf[64];
	clockid_t cid;
	cbl_msg *m;
	long cpu_ms;
	size_t len;
	int fd, probe;

	test_server_start(&ts, sctx, "tcp://127.0.0.1:0", CBL_PLAINTEXT);
	ATF_REQUIRE_EQ(0, pthread_getcpuclockid(ts.thr, &cid));
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = htons((uint16_t)atoi(strrchr(ts.uri, ':') + 1));
	ATF_REQUIRE((fd = socket(AF_INET, SOCK_STREAM, 0)) != -1);
	/* No descriptor below "probe" is free: accept(2) gets EMFILE. */
	ATF_REQUIRE((probe = dup(0)) != -1);
	close(probe);
	ATF_REQUIRE_EQ(0, getrlimit(RLIMIT_NOFILE, &old));
	low = old;
	low.rlim_cur = (rlim_t)probe;
	ATF_REQUIRE_EQ(0, setrlimit(RLIMIT_NOFILE, &low));
	ATF_REQUIRE_EQ(0, connect(fd, (struct sockaddr *)&sin, sizeof(sin)));
	clock_gettime(cid, &a);
	usleep(1000000);
	clock_gettime(cid, &b);
	ATF_REQUIRE_EQ(0, setrlimit(RLIMIT_NOFILE, &old));
	cpu_ms = (b.tv_sec - a.tv_sec) * 1000 +
	    (b.tv_nsec - a.tv_nsec) / 1000000;
	ATF_REQUIRE_MSG(cpu_ms < 300, "loop used %ld ms of CPU in 1 s", cpu_ms);
	/* The listener resumed: the waiting connection is served. */
	len = mkframe(buf, sizeof(buf), 0, 4, CBL_F_REQUEST, 7, 0, "A0");
	raw_write(fd, buf, len);
	ATF_REQUIRE((m = raw_read_msg(sctx, fd)) != NULL);
	ATF_REQUIRE_EQ(7, cbl_msg_seq(m));
	cbl_msg_free(m);
	close(fd);
	test_server_stop(&ts);
	cbl_ctx_free(sctx);
}

/*
 * A CBL_CF_NONBLOCK client whose first address refuses moves on to the
 * next: "localhost" as ::1 then 127.0.0.1, with a server on 127.0.0.1.
 */
ATF_TC_WITHOUT_HEAD(nonblock_failover);
ATF_TC_BODY(nonblock_failover, tc)
{
	struct addrinfo hints = { .ai_socktype = SOCK_STREAM }, *res;
	struct test_server ts;
	cbl_ctx *sctx = test_ctx(), *cctx = test_ctx();
	struct pollfd pfd;
	cbl_conn *c;
	char uri[64];
	int events, timeout, error, first;

	ATF_REQUIRE_EQ(0, getaddrinfo("localhost", "1", &hints, &res));
	first = res->ai_family;
	freeaddrinfo(res);
	if (first != AF_INET6)
		atf_tc_skip("localhost does not resolve to ::1 first");
	test_server_start(&ts, sctx, "tcp://127.0.0.1:0", CBL_PLAINTEXT);
	snprintf(uri, sizeof(uri), "tcp://localhost:%s",
	    strrchr(ts.uri, ':') + 1);
	ATF_REQUIRE_EQ(0, cbl_conn_new(cctx, uri,
	    CBL_PLAINTEXT | CBL_CF_NONBLOCK, &c));
	error = cbl_conn_connect(c);
	ATF_REQUIRE_MSG(error == EINPROGRESS, "connect: %d", error);
	for (int i = 0; i < 200 && !cbl_conn_is_open(c); i++) {
		ATF_REQUIRE_EQ(0, cbl_conn_interest(c, &events, &timeout));
		pfd.fd = cbl_conn_fd(c);
		pfd.events = POLLOUT;
		pfd.revents = 0;
		(void)poll(&pfd, 1, 10);
		error = cbl_conn_process(c, (pfd.revents & POLLOUT) != 0 ?
		    CBL_EV_WRITE : 0);
		ATF_REQUIRE_MSG(error == 0, "%s", cbl_conn_errstr(c));
	}
	ATF_REQUIRE(cbl_conn_is_open(c));
	cbl_conn_free(c);
	test_server_stop(&ts);
	cbl_ctx_free(sctx);
	cbl_ctx_free(cctx);
}

static void
count_fire(cbl_timer *t __unused, void *arg)
{

	(*(int *)arg)++;
}

static void
ignore_sig(int sig __unused, void *arg __unused)
{
}

/*
 * A one-shot timer's handle stays valid after it fired, until cancelled;
 * a signal's action is back to what it was once the loop is freed.
 */
ATF_TC_WITHOUT_HEAD(timer_and_signal_lifetime);
ATF_TC_BODY(timer_and_signal_lifetime, tc)
{
	struct sigaction sa;
	cbl_ctx *ctx = test_ctx();
	cbl_loop *loop;
	cbl_timer *t;
	int fired = 0;

	ATF_REQUIRE_EQ(0, cbl_loop_new(ctx, &loop));
	ATF_REQUIRE_EQ(0, cbl_loop_timer(loop, 10, 0, count_fire, &fired, &t));
	for (int i = 0; i < 100 && fired == 0; i++)
		ATF_REQUIRE_EQ(0, cbl_loop_run_once(loop, 10));
	ATF_REQUIRE_EQ(1, fired);
	ATF_REQUIRE_EQ(0, cbl_loop_run_once(loop, 30));
	ATF_REQUIRE_EQ(1, fired);		/* one-shot */
	cbl_timer_cancel(t);		/* still a valid handle */
	ATF_REQUIRE_EQ(0, cbl_loop_run_once(loop, 0));

	ATF_REQUIRE_EQ(0, cbl_loop_signal(loop, SIGUSR2, ignore_sig, NULL));
	ATF_REQUIRE_EQ(0, sigaction(SIGUSR2, NULL, &sa));
	ATF_REQUIRE(sa.sa_handler == SIG_IGN);
	cbl_loop_free(loop);
	ATF_REQUIRE_EQ(0, sigaction(SIGUSR2, NULL, &sa));
	ATF_REQUIRE(sa.sa_handler == SIG_DFL);
	cbl_ctx_free(ctx);
}

/* A context in use cannot be freed. */
ATF_TC_WITHOUT_HEAD(ctx_busy);
ATF_TC_BODY(ctx_busy, tc)
{
	cbl_ctx *ctx = test_ctx();
	cbl_listener *l;
	cbl_loop *loop;
	cbl_conn *c;

	ATF_REQUIRE_EQ(0, cbl_loop_new(ctx, &loop));
	ATF_REQUIRE_EQ(EBUSY, cbl_ctx_free(ctx));
	cbl_loop_free(loop);
	ATF_REQUIRE_EQ(0, cbl_listener_new(ctx, "tcp://127.0.0.1:0",
	    CBL_PLAINTEXT, &l));
	ATF_REQUIRE_EQ(EBUSY, cbl_ctx_free(ctx));
	cbl_listener_free(l);
	ATF_REQUIRE_EQ(0, cbl_conn_new(ctx, "tcp://127.0.0.1:1", CBL_PLAINTEXT,
	    &c));
	ATF_REQUIRE_EQ(EBUSY, cbl_ctx_free(ctx));
	cbl_conn_free(c);
	ATF_REQUIRE_EQ(0, cbl_ctx_free(ctx));
}

/*
 * A peer that sends requests and never reads the answers.  The answers
 * (errors here) must not be dropped, so they queue beyond sendq_bytes, but
 * only up to twice that: then the connection is given up, rather than
 * growing its queue for as long as the peer keeps asking.
 */
ATF_TC_WITHOUT_HEAD(answer_flood);
ATF_TC_BODY(answer_flood, tc)
{
	cbl_ctx *ctx = test_ctx();
	struct cbl_conn_stats st;
	unsigned char req[CBL_HDRLEN], *batch;
	const size_t sendq = 64 * 1024, nbatch = 512;
	struct timespec t0, t;
	struct pollfd pfd;
	char uri[64];
	uint16_t port;
	cbl_conn *c;
	size_t len, off = 0, peak = 0;
	ssize_t n;
	int lfd, fd, small = 16 * 1024, error = 0;

	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(ctx, CBL_LIM_SENDQ_BYTES, sendq));
	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(ctx, CBL_LIM_STREAM_CLOSE_MS,
	    300));
	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(ctx, CBL_LIM_IDLE_MS, 0));
	lfd = raw_listen(&port);
	ATF_REQUIRE(setsockopt(lfd, SOL_SOCKET, SO_RCVBUF, &small,
	    sizeof(small)) == 0);
	snprintf(uri, sizeof(uri), "tcp://127.0.0.1:%u", port);
	c = client_connect(ctx, uri);
	ATF_REQUIRE(setsockopt(cbl_conn_fd(c), SOL_SOCKET, SO_SNDBUF, &small,
	    sizeof(small)) == 0);
	ATF_REQUIRE((fd = accept(lfd, NULL, NULL)) != -1);
	ATF_REQUIRE(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);

	/* Requests for a family nobody registered: each gets an ERROR. */
	len = mkframe(req, sizeof(req), 4, 2, CBL_F_REQUEST, 1, 0, NULL);
	ATF_REQUIRE((batch = malloc(len * nbatch)) != NULL);
	for (size_t i = 0; i < nbatch; i++)
		memcpy(batch + i * len, req, len);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	do {
		/* A write may stop inside a frame: go on from there. */
		n = write(fd, batch + off, len * nbatch - off);
		if (n > 0)
			off = (off + (size_t)n) % (len * nbatch);
		pfd.fd = cbl_conn_fd(c);
		pfd.events = POLLIN | POLLOUT;
		pfd.revents = 0;
		(void)poll(&pfd, 1, 10);
		error = cbl_conn_process(c, CBL_EV_READ | CBL_EV_WRITE);
		ATF_REQUIRE_EQ(0, cbl_conn_stats(c, &st));
		if (st.txq_bytes > peak)
			peak = st.txq_bytes;
		clock_gettime(CLOCK_MONOTONIC, &t);
	} while (error == 0 && t.tv_sec - t0.tv_sec < 60);
	ATF_REQUIRE_MSG(error != 0, "still open, %zu bytes queued", peak);
	ATF_REQUIRE(!cbl_conn_is_open(c));
	ATF_REQUIRE_MSG(peak > sendq && peak <= 2 * sendq,
	    "queue peaked at %zu: %s", peak, cbl_conn_errstr(c));
	free(batch);
	close(fd);
	close(lfd);
	cbl_conn_free(c);
	ATF_REQUIRE_EQ(0, cbl_ctx_free(ctx));
}

/*
 * A listener freed while its loop runs, from a callback on the loop and
 * from another thread: the loop lets go of it without touching it again.
 */
static void
free_listener_cb(void *arg)
{

	cbl_listener_free(arg);
}

ATF_TC_WITHOUT_HEAD(listener_free_running);
ATF_TC_BODY(listener_free_running, tc)
{
	struct sockaddr_in sin = { .sin_len = sizeof(sin),
	    .sin_family = AF_INET };
	struct sockaddr_storage ss;
	cbl_ctx *ctx = test_ctx();
	cbl_listener *l[2];
	cbl_loop *loop;
	pthread_t thr;
	int fd, i;

	ATF_REQUIRE_EQ(0, cbl_loop_new(ctx, &loop));
	for (i = 0; i < 2; i++) {
		ATF_REQUIRE_EQ(0, cbl_listener_new(ctx, "tcp://127.0.0.1:0",
		    CBL_PLAINTEXT, &l[i]));
		ATF_REQUIRE_EQ(0, cbl_listener_start(l[i], loop));
	}
	ATF_REQUIRE_EQ(0, pthread_create(&thr, NULL, loop_thread, loop));
	for (i = 0; i < 2; i++) {
		ATF_REQUIRE_EQ(0, cbl_listener_addr(l[i], &ss, NULL));
		sin.sin_port = ((struct sockaddr_in *)&ss)->sin_port;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		/* A connection is pending when the listener goes. */
		ATF_REQUIRE((fd = socket(AF_INET, SOCK_STREAM, 0)) != -1);
		ATF_REQUIRE(connect(fd, (struct sockaddr *)&sin,
		    sizeof(sin)) == 0);
		if (i == 0)
			ATF_REQUIRE_EQ(0, cbl_loop_post(loop,
			    free_listener_cb, l[i]));
		else
			cbl_listener_free(l[i]);
		close(fd);
		/* The port stops answering once the loop got to it. */
		for (int tries = 0; tries < 200; tries++) {
			ATF_REQUIRE((fd = socket(AF_INET, SOCK_STREAM,
			    0)) != -1);
			if (connect(fd, (struct sockaddr *)&sin,
			    sizeof(sin)) != 0) {
				close(fd);
				break;
			}
			close(fd);
			usleep(10000);
			ATF_REQUIRE(tries < 199);
		}
	}
	cbl_loop_stop(loop);
	pthread_join(thr, NULL);
	cbl_loop_free(loop);
	ATF_REQUIRE_EQ(0, cbl_ctx_free(ctx));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, hello_limits);
	ATF_TP_ADD_TC(tp, plaintext_opt_in);
	ATF_TP_ADD_TC(tp, connect_refused);
	ATF_TP_ADD_TC(tp, unknown_family);
	ATF_TP_ADD_TC(tp, out_of_order);
	ATF_TP_ADD_TC(tp, fragmented_reply);
	ATF_TP_ADD_TC(tp, big_reply);
	ATF_TP_ADD_TC(tp, request_timeout);
	ATF_TP_ADD_TC(tp, server_oversize);
	ATF_TP_ADD_TC(tp, server_bad_magic);
	ATF_TP_ADD_TC(tp, server_recovers);
	ATF_TP_ADD_TC(tp, first_frame_timeout);
	ATF_TP_ADD_TC(tp, idle_timeout);
	ATF_TP_ADD_TC(tp, loop_client);
	ATF_TP_ADD_TC(tp, nonblock_idle);
	ATF_TP_ADD_TC(tp, wildcard_both_families);
	ATF_TP_ADD_TC(tp, accept_emfile);
	ATF_TP_ADD_TC(tp, nonblock_failover);
	ATF_TP_ADD_TC(tp, timer_and_signal_lifetime);
	ATF_TP_ADD_TC(tp, ctx_busy);
	ATF_TP_ADD_TC(tp, answer_flood);
	ATF_TP_ADD_TC(tp, listener_free_running);
	return (atf_no_error());
}
