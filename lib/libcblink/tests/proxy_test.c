/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The PROXY protocol on CBL_LF_PROXY listeners, seen from a raw socket:
 * versions 1 and 2, the address the server reports, headers that arrive
 * in pieces or together with the first frame, and the headers refused.
 */

#include <sys/param.h>

#include "cbl_net_test.h"

static const unsigned char pp2_sig[12] = {
	0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
};

/* src 192.0.2.7:4321, dst 127.0.0.1:8080 */
static const unsigned char addrs4[12] = {
	192, 0, 2, 7, 127, 0, 0, 1, 0x10, 0xe1, 0x1f, 0x90,
};

/* src [2001:db8::7]:4321, dst [::1]:8080 */
static const unsigned char addrs6[36] = {
	0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	0x10, 0xe1, 0x1f, 0x90,
};

/* What the server's on_open saw last. */
static struct {
	pthread_mutex_t		 mtx;
	struct sockaddr_storage	 ss;
	uint32_t		 flags;
	bool			 open;
} seen = { .mtx = PTHREAD_MUTEX_INITIALIZER };

static void
on_open(cbl_conn *conn, void *arg __unused)
{
	const cbl_peer *p = cbl_conn_peer(conn);

	pthread_mutex_lock(&seen.mtx);
	memset(&seen.ss, 0, sizeof(seen.ss));
	(void)cbl_peer_addr(p, &seen.ss, NULL);
	seen.flags = cbl_peer_flags(p);
	seen.open = true;
	pthread_mutex_unlock(&seen.mtx);
}

static void
proxy_server(struct test_server *ts, uint64_t handshake_ms)
{
	static const struct cbl_conn_cbs cbs = { .on_open = on_open };
	cbl_ctx *ctx = test_ctx();

	ATF_REQUIRE_EQ(0, cbl_ctx_set_conn_cbs(ctx, &cbs, NULL));
	if (handshake_ms != 0)
		ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(ctx, CBL_LIM_HANDSHAKE_MS,
		    handshake_ms));
	test_server_start(ts, ctx, "tcp://127.0.0.1:0",
	    CBL_PLAINTEXT | CBL_LF_PROXY);
}

static void
proxy_server_stop(struct test_server *ts)
{

	test_server_stop(ts);
	cbl_ctx_free(ts->ctx);
}

/* A version 2 header; "tlv" bytes of PP2_TYPE_NOOP follow the addresses. */
static size_t
pp2(unsigned char *b, int cmd, int fam, const void *addrs, size_t alen,
    size_t tlv)
{
	size_t len = alen + tlv;

	memcpy(b, pp2_sig, sizeof(pp2_sig));
	b[12] = (unsigned char)(0x20 | cmd);
	b[13] = (unsigned char)fam;
	b[14] = (unsigned char)(len >> 8);
	b[15] = (unsigned char)len;
	if (alen > 0)
		memcpy(b + 16, addrs, alen);
	if (tlv > 0) {
		ATF_REQUIRE(tlv >= 3);
		memset(b + 16 + alen, 0, tlv);
		b[16 + alen] = 0x04;
		b[16 + alen + 2] = (unsigned char)(tlv - 3);
	}
	return (16 + len);
}

/* A ping on "fd" is answered: whatever preceded it was consumed exactly. */
static void
ping_ok(struct test_server *ts, int fd, const void *pre, size_t prelen)
{
	unsigned char buf[1024];
	cbl_msg *m;
	size_t len;

	ATF_REQUIRE(prelen < sizeof(buf) - 64);
	if (prelen > 0)
		memcpy(buf, pre, prelen);
	len = prelen + mkframe(buf + prelen, sizeof(buf) - prelen, 0, 4,
	    CBL_F_REQUEST, 9, 0, "A0");
	raw_write(fd, buf, len);
	ATF_REQUIRE((m = raw_read_msg(ts->ctx, fd)) != NULL);
	ATF_REQUIRE_EQ(0, cbl_msg_err_code(m));
	ATF_REQUIRE_EQ(9, cbl_msg_seq(m));
	cbl_msg_free(m);
}

/* The header and the first frame in a single write. */
static void
through(struct test_server *ts, const void *hdr, size_t hlen)
{
	int fd = raw_connect(ts->uri);

	ping_ok(ts, fd, hdr, hlen);
	close(fd);
}

static void
expect_addr(int af, const char *addr, uint16_t port, bool proxied)
{
	const struct sockaddr_in *sin;
	const struct sockaddr_in6 *sin6;
	char s[INET6_ADDRSTRLEN];
	uint16_t p;

	pthread_mutex_lock(&seen.mtx);
	ATF_REQUIRE(seen.open);
	ATF_REQUIRE_EQ(af, seen.ss.ss_family);
	if (af == AF_INET) {
		sin = (const struct sockaddr_in *)&seen.ss;
		inet_ntop(AF_INET, &sin->sin_addr, s, sizeof(s));
		p = ntohs(sin->sin_port);
	} else {
		sin6 = (const struct sockaddr_in6 *)&seen.ss;
		inet_ntop(AF_INET6, &sin6->sin6_addr, s, sizeof(s));
		p = ntohs(sin6->sin6_port);
	}
	ATF_CHECK_STREQ(addr, s);
	if (port != 0)
		ATF_CHECK_EQ(port, p);
	ATF_CHECK_EQ(proxied, (seen.flags & CBL_PEER_PROXIED) != 0);
	seen.open = false;
	pthread_mutex_unlock(&seen.mtx);
}

ATF_TC_WITHOUT_HEAD(v2);
ATF_TC_BODY(v2, tc)
{
	static const unsigned char unix_addrs[216];
	struct test_server ts;
	unsigned char h[300];

	proxy_server(&ts, 0);
	through(&ts, h, pp2(h, 1, 0x11, addrs4, sizeof(addrs4), 0));
	expect_addr(AF_INET, "192.0.2.7", 4321, true);
	through(&ts, h, pp2(h, 1, 0x21, addrs6, sizeof(addrs6), 0));
	expect_addr(AF_INET6, "2001:db8::7", 4321, true);
	/* TLVs are skipped. */
	through(&ts, h, pp2(h, 1, 0x11, addrs4, sizeof(addrs4), 40));
	expect_addr(AF_INET, "192.0.2.7", 4321, true);
	/* LOCAL (a health check) and unspecified: the socket's address. */
	through(&ts, h, pp2(h, 0, 0x00, NULL, 0, 0));
	expect_addr(AF_INET, "127.0.0.1", 0, false);
	through(&ts, h, pp2(h, 1, 0x00, NULL, 0, 0));
	expect_addr(AF_INET, "127.0.0.1", 0, false);
	/* AF_UNIX addresses are not TCP: also the socket's address. */
	through(&ts, h, pp2(h, 1, 0x31, unix_addrs, sizeof(unix_addrs), 0));
	expect_addr(AF_INET, "127.0.0.1", 0, false);
	proxy_server_stop(&ts);
}

ATF_TC_WITHOUT_HEAD(v1);
ATF_TC_BODY(v1, tc)
{
	static const char tcp4[] =
	    "PROXY TCP4 192.0.2.7 127.0.0.1 4321 8080\r\n";
	static const char tcp6[] =
	    "PROXY TCP6 2001:db8::7 ::1 4321 8080\r\n";
	static const char unknown[] = "PROXY UNKNOWN\r\n";
	static const char unknown_more[] =
	    "PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n";
	struct test_server ts;

	proxy_server(&ts, 0);
	through(&ts, tcp4, strlen(tcp4));
	expect_addr(AF_INET, "192.0.2.7", 4321, true);
	through(&ts, tcp6, strlen(tcp6));
	expect_addr(AF_INET6, "2001:db8::7", 4321, true);
	through(&ts, unknown, strlen(unknown));
	expect_addr(AF_INET, "127.0.0.1", 0, false);
	through(&ts, unknown_more, strlen(unknown_more));
	expect_addr(AF_INET, "127.0.0.1", 0, false);
	proxy_server_stop(&ts);
}

/* Headers that arrive a few bytes at a time. */
ATF_TC_WITHOUT_HEAD(pieces);
ATF_TC_BODY(pieces, tc)
{
	static const char tcp4[] =
	    "PROXY TCP4 192.0.2.7 127.0.0.1 4321 8080\r\n";
	struct test_server ts;
	unsigned char h[128];
	size_t len;
	int fd;

	proxy_server(&ts, 0);
	len = pp2(h, 1, 0x11, addrs4, sizeof(addrs4), 8);
	fd = raw_connect(ts.uri);
	for (size_t i = 0; i < len; i += 5) {
		raw_write(fd, h + i, len - i < 5 ? len - i : 5);
		usleep(20000);
	}
	ping_ok(&ts, fd, NULL, 0);
	close(fd);
	expect_addr(AF_INET, "192.0.2.7", 4321, true);

	fd = raw_connect(ts.uri);
	for (size_t i = 0; i < strlen(tcp4); i += 7) {
		raw_write(fd, tcp4 + i, strlen(tcp4) - i < 7 ?
		    strlen(tcp4) - i : 7);
		usleep(20000);
	}
	ping_ok(&ts, fd, NULL, 0);
	close(fd);
	expect_addr(AF_INET, "192.0.2.7", 4321, true);
	proxy_server_stop(&ts);
}

/* A connection whose header is refused is closed; others carry on. */
static void
refused(struct test_server *ts, const void *p, size_t len)
{
	int fd = raw_connect(ts->uri);

	raw_write(fd, p, len);
	ATF_REQUIRE_MSG(raw_eof(fd, 3000), "header not refused");
	close(fd);
}

ATF_TC_WITHOUT_HEAD(refused);
ATF_TC_BODY(refused, tc)
{
	static const char *const bad1[] = {
		"PROXY TCP4 192.0.2.7 127.0.0.1 4321\r\n",
		"PROXY TCP4 192.0.2.7 127.0.0.1 4321 8080 9\r\n",
		"PROXY TCP4 192.0.2.300 127.0.0.1 4321 8080\r\n",
		"PROXY TCP4 2001:db8::7 127.0.0.1 4321 8080\r\n",
		"PROXY TCP6 192.0.2.7 ::1 4321 8080\r\n",
		"PROXY TCP4 192.0.2.7 127.0.0.1 04321 8080\r\n",
		"PROXY TCP4 192.0.2.7 127.0.0.1 65536 8080\r\n",
		"PROXY TCP4 192.0.2.7 127.0.0.1 4321 8080\n",
		"PROXY UDP4 192.0.2.7 127.0.0.1 4321 8080\r\n",
		"PROXY\nTCP4 192.0.2.7 127.0.0.1 4321 8080\r\n",
		"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
	};
	struct test_server ts;
	unsigned char h[700], frame[64];
	size_t len;
	char line[200];

	proxy_server(&ts, 0);
	for (size_t i = 0; i < nitems(bad1); i++)
		refused(&ts, bad1[i], strlen(bad1[i]));
	/* No line end within 107 bytes. */
	memset(line, 'A', sizeof(line));
	memcpy(line, "PROXY TCP4 ", 11);
	refused(&ts, line, sizeof(line));
	/* No header at all: a frame straight away. */
	len = mkframe(frame, sizeof(frame), 0, 4, CBL_F_REQUEST, 1, 0, "A0");
	refused(&ts, frame, len);
	/* Version 2: wrong version, unknown command, too long, short. */
	len = pp2(h, 1, 0x11, addrs4, sizeof(addrs4), 0);
	h[12] = 0x31;
	refused(&ts, h, len);
	len = pp2(h, 2, 0x11, addrs4, sizeof(addrs4), 0);
	refused(&ts, h, len);
	len = pp2(h, 1, 0x11, addrs4, sizeof(addrs4), 600);
	refused(&ts, h, 16);
	len = pp2(h, 1, 0x11, addrs4, 8, 0);
	refused(&ts, h, len);
	len = pp2(h, 1, 0x21, addrs6, 24, 0);
	refused(&ts, h, len);
	/* The listener still works. */
	through(&ts, h, pp2(h, 1, 0x11, addrs4, sizeof(addrs4), 0));
	expect_addr(AF_INET, "192.0.2.7", 4321, true);
	proxy_server_stop(&ts);
}

/* An incomplete header is bound by handshake_timeout. */
ATF_TC_WITHOUT_HEAD(timeout);
ATF_TC_BODY(timeout, tc)
{
	struct test_server ts;
	int fd;

	proxy_server(&ts, 200);
	fd = raw_connect(ts.uri);
	raw_write(fd, "PROXY TCP4 192.0", 16);
	ATF_REQUIRE(raw_eof(fd, 3000));
	close(fd);
	proxy_server_stop(&ts);
}

ATF_TC_WITHOUT_HEAD(flags);
ATF_TC_BODY(flags, tc)
{
	cbl_ctx *ctx = test_ctx();
	cbl_listener *l;
	cbl_conn *c;

	/* Listeners only, and on TCP only. */
	ATF_REQUIRE_EQ(EINVAL, cbl_conn_new(ctx, "tcp://127.0.0.1:1",
	    CBL_PLAINTEXT | CBL_LF_PROXY, &c));
	ATF_REQUIRE_EQ(EINVAL, cbl_listener_new(ctx, "unix:/tmp/x",
	    CBL_LF_PROXY, &l));
	ATF_REQUIRE_EQ(EINVAL, cbl_listener_new(ctx, "sctp://127.0.0.1:0",
	    CBL_PLAINTEXT | CBL_LF_PROXY, &l));
	ATF_REQUIRE_EQ(0, cbl_listener_new(ctx, "tcp://127.0.0.1:0",
	    CBL_PLAINTEXT | CBL_LF_PROXY, &l));
	cbl_listener_free(l);
	cbl_ctx_free(ctx);
}

/* A PROXY listener that takes the header from "nets" only. */
static void
proxy_server_nets(struct test_server *ts, const char *const *nets, size_t n)
{
	struct sockaddr_storage ss;

	memset(ts, 0, sizeof(*ts));
	ts->ctx = test_ctx();
	ATF_REQUIRE_EQ(0, cbl_loop_new(ts->ctx, &ts->loop));
	ATF_REQUIRE_EQ(0, cbl_listener_new(ts->ctx, "tcp://127.0.0.1:0",
	    CBL_PLAINTEXT | CBL_LF_PROXY, &ts->l));
	for (size_t i = 0; i < n; i++)
		ATF_REQUIRE_EQ(0, cbl_listener_add_proxy(ts->l, nets[i]));
	ATF_REQUIRE_EQ(0, cbl_listener_start(ts->l, ts->loop));
	ATF_REQUIRE_EQ(EBUSY, cbl_listener_add_proxy(ts->l, "10.0.0.1"));
	ATF_REQUIRE_EQ(0, cbl_listener_addr(ts->l, &ss, NULL));
	snprintf(ts->uri, sizeof(ts->uri), "tcp://127.0.0.1:%u",
	    ntohs(((struct sockaddr_in *)&ss)->sin_port));
	ATF_REQUIRE_EQ(0, pthread_create(&ts->thr, NULL, test_server_thread,
	    ts));
}

/* Only the allowed proxies may send the header. */
ATF_TC_WITHOUT_HEAD(allowed_proxies);
ATF_TC_BODY(allowed_proxies, tc)
{
	static const char *const bad[] = { "300.1.1.1", "10.0.0.0/33",
	    "::1/129", "x", "10.0.0.0/", "10.0.0.0/8x" };
	static const char *const elsewhere[] = { "192.0.2.0/24" };
	static const char *const here[] = { "10.0.0.0/8", "::1",
	    "127.0.0.0/8" };
	struct test_server ts;
	unsigned char h[128];
	cbl_ctx *ctx = test_ctx();
	cbl_listener *l;

	ATF_REQUIRE_EQ(0, cbl_listener_new(ctx, "tcp://127.0.0.1:0",
	    CBL_PLAINTEXT, &l));
	ATF_REQUIRE_EQ(EINVAL, cbl_listener_add_proxy(l, "127.0.0.1"));
	cbl_listener_free(l);
	ATF_REQUIRE_EQ(0, cbl_listener_new(ctx, "tcp://127.0.0.1:0",
	    CBL_PLAINTEXT | CBL_LF_PROXY, &l));
	for (size_t i = 0; i < nitems(bad); i++)
		ATF_REQUIRE_EQ_MSG(EINVAL, cbl_listener_add_proxy(l, bad[i]),
		    "%s", bad[i]);
	cbl_listener_free(l);
	ATF_REQUIRE_EQ(0, cbl_ctx_free(ctx));

	proxy_server_nets(&ts, elsewhere, nitems(elsewhere));
	refused(&ts, h, pp2(h, 1, 0x11, addrs4, sizeof(addrs4), 0));
	proxy_server_stop(&ts);

	proxy_server_nets(&ts, here, nitems(here));
	through(&ts, h, pp2(h, 1, 0x11, addrs4, sizeof(addrs4), 0));
	proxy_server_stop(&ts);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, v2);
	ATF_TP_ADD_TC(tp, v1);
	ATF_TP_ADD_TC(tp, pieces);
	ATF_TP_ADD_TC(tp, refused);
	ATF_TP_ADD_TC(tp, timeout);
	ATF_TP_ADD_TC(tp, flags);
	ATF_TP_ADD_TC(tp, allowed_proxies);
	return (atf_no_error());
}
