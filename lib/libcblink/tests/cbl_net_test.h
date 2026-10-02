/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* Network helpers for the libcblink atf-c tests. */

#ifndef _CBL_NET_TEST_H_
#define	_CBL_NET_TEST_H_

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>

#include "cbl_test.h"

/* A server: listener + loop running in its own thread. */
struct test_server {
	cbl_ctx		*ctx;
	cbl_loop	*loop;
	cbl_listener	*l;
	pthread_t	 thr;
	char		 uri[128];
};

static void *
test_server_thread(void *arg)
{
	struct test_server *ts = arg;

	(void)cbl_loop_run(ts->loop);
	return (NULL);
}

/* Listen on "base" (e.g. "tcp://127.0.0.1:0"); ts->uri gets the address. */
static inline void
test_server_start(struct test_server *ts, cbl_ctx *ctx, const char *base,
    uint32_t flags)
{
	struct sockaddr_storage ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ss;

	memset(ts, 0, sizeof(*ts));
	ts->ctx = ctx;
	ATF_REQUIRE_EQ(0, cbl_loop_new(ctx, &ts->loop));
	ATF_REQUIRE_EQ(0, cbl_listener_new(ctx, base, flags, &ts->l));
	ATF_REQUIRE_EQ(0, cbl_listener_start(ts->l, ts->loop));
	ATF_REQUIRE_EQ(0, cbl_listener_addr(ts->l, &ss, NULL));
	if (ss.ss_family == AF_INET)
		snprintf(ts->uri, sizeof(ts->uri), "tcp://127.0.0.1:%u",
		    ntohs(sin->sin_port));
	else
		strlcpy(ts->uri, base, sizeof(ts->uri));
	ATF_REQUIRE_EQ(0, pthread_create(&ts->thr, NULL, test_server_thread,
	    ts));
}

static inline void
test_server_stop(struct test_server *ts)
{

	cbl_loop_stop(ts->loop);
	pthread_join(ts->thr, NULL);
	cbl_listener_free(ts->l);
	cbl_loop_free(ts->loop);
}

/* Raw TCP helpers: the test plays a peer byte by byte. */
static inline int
raw_listen(uint16_t *portp)
{
	struct sockaddr_in sin = { .sin_len = sizeof(sin),
	    .sin_family = AF_INET };
	socklen_t len = sizeof(sin);
	int fd;

	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ATF_REQUIRE((fd = socket(AF_INET, SOCK_STREAM, 0)) != -1);
	ATF_REQUIRE(bind(fd, (struct sockaddr *)&sin, sizeof(sin)) == 0);
	ATF_REQUIRE(listen(fd, 8) == 0);
	ATF_REQUIRE(getsockname(fd, (struct sockaddr *)&sin, &len) == 0);
	*portp = ntohs(sin.sin_port);
	return (fd);
}

static inline int
raw_connect(const char *uri)
{
	struct sockaddr_in sin = { .sin_len = sizeof(sin),
	    .sin_family = AF_INET };
	const char *colon = strrchr(uri, ':');
	int fd;

	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = htons((uint16_t)atoi(colon + 1));
	ATF_REQUIRE((fd = socket(AF_INET, SOCK_STREAM, 0)) != -1);
	ATF_REQUIRE(connect(fd, (struct sockaddr *)&sin, sizeof(sin)) == 0);
	return (fd);
}

static inline void
raw_write(int fd, const void *p, size_t len)
{
	ATF_REQUIRE_EQ((ssize_t)len, write(fd, p, len));
}

/* Read exactly "len" bytes; returns false on EOF. */
static inline bool
raw_read_full(int fd, void *p, size_t len, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	size_t have = 0;
	ssize_t n;

	while (have < len) {
		ATF_REQUIRE_MSG(poll(&pfd, 1, timeout_ms) == 1,
		    "timed out reading from peer");
		n = read(fd, (char *)p + have, len - have);
		if (n <= 0)
			return (false);
		have += (size_t)n;
	}
	return (true);
}

/* Read one frame; NULL on EOF. */
static inline cbl_msg *
raw_read_msg(cbl_ctx *ctx, int fd)
{
	unsigned char hdr[CBL_HDRLEN], *buf;
	cbl_msg *msg;
	uint32_t len;

	if (!raw_read_full(fd, hdr, sizeof(hdr), 5000))
		return (NULL);
	len = (uint32_t)hdr[4] << 24 | hdr[5] << 16 | hdr[6] << 8 | hdr[7];
	ATF_REQUIRE(len >= CBL_HDRLEN && len < 16 * 1024 * 1024);
	ATF_REQUIRE((buf = malloc(len)) != NULL);
	memcpy(buf, hdr, sizeof(hdr));
	ATF_REQUIRE(raw_read_full(fd, buf + CBL_HDRLEN, len - CBL_HDRLEN,
	    5000));
	ATF_REQUIRE_EQ(0, cbl_frame_decode(ctx, buf, len, NULL, &msg));
	free(buf);
	return (msg);
}

static inline void
raw_send_msg(int fd, cbl_msg *msg)
{
	const void *f;
	size_t len;

	ATF_REQUIRE_EQ(0, cbl_msg_encode(msg, &f, &len));
	raw_write(fd, f, len);
	cbl_msg_free(msg);
}

/* True if the peer closed the connection within "timeout_ms". */
static inline bool
raw_eof(int fd, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	char c;

	if (poll(&pfd, 1, timeout_ms) != 1)
		return (false);
	return (read(fd, &c, 1) <= 0);
}

/*
 * True if the peer closed the connection within "timeout_ms", reading and
 * discarding whatever it sends first (keepalive pings, say).
 */
static inline bool
raw_closed(int fd, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	char buf[512];

	for (;;) {
		if (poll(&pfd, 1, timeout_ms) != 1)
			return (false);
		if (read(fd, buf, sizeof(buf)) <= 0)
			return (true);
	}
}

#endif /* !_CBL_NET_TEST_H_ */
