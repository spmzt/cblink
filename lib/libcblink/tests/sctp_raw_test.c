/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* Plaintext SCTP server behaviour seen from a raw SCTP socket. */

#include <netinet/sctp.h>

#include <stdlib.h>
#include <string.h>

#include "cbl_net_test.h"

enum { S_ECHO = 1, S_FEED };

#define	FEED_ITEMS	3
#define	SMALL_MAX	(256 * 1024)	/* the server's max_frame */

static int
secho(cbl_req *req, const cbl_msg *msg, void *arg __unused)
{
	cbl_msg *r;
	int error;

	if ((error = cbl_req_reply_new(req, 0, &r)) != 0)
		return (error);
	if (cbl_msg_attr(msg, 1) != NULL)
		cbl_put_attr(r, 1, cbl_msg_attr(msg, 1));
	return (cbl_req_send(req, r));
}

static void
sfeed_close(cbl_stream *s __unused, int code __unused,
    const char *text __unused, void *arg __unused)
{
}

static const struct cbl_stream_cbs sfeed_cbs = {
	.on_close = sfeed_close,
};

static int
sfeed(cbl_req *req __unused, const cbl_msg *msg __unused, cbl_stream *s,
    void *arg __unused)
{
	cbl_msg *m;
	int error;

	if ((error = cbl_stream_accept(s, NULL, 0, &sfeed_cbs, NULL)) != 0)
		return (error);
	for (int i = 0; i < FEED_ITEMS; i++) {
		ATF_REQUIRE_EQ(0, cbl_stream_msg_new(s, &m));
		cbl_put_uint(m, 1, (uint64_t)i);
		ATF_REQUIRE_EQ(0, cbl_stream_send(s, m));
	}
	return (cbl_stream_half_close(s));
}

static const struct cbl_op s_ops[] = {
	{ .cmd = S_ECHO, .name = "echo", .flags = CBL_OPF_DO, .doit = secho },
	{ .cmd = S_FEED, .name = "feed", .flags = CBL_OPF_PUSH,
	  .stream_open = sfeed },
};
static const struct cbl_family_def s_def = {
	.abi = CBL_FAMILY_ABI, .name = "sctpraw", .version = 1,
	.ops = s_ops, .nops = nitems(s_ops),
};

struct sfx {
	cbl_ctx		*ctx;
	cbl_loop	*loop;
	cbl_listener	*l;
	cbl_family	*fam;
	pthread_t	 thr;
	struct sockaddr_in sin;
};

static void *
sloop(void *arg)
{

	(void)cbl_loop_run(arg);
	return (NULL);
}

static void
sfx_start(struct sfx *f)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);
	int fd;

	/* sctp(4) may be a module that is not loaded. */
	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) == -1)
		atf_tc_skip("SCTP is not available: %s", strerror(errno));
	close(fd);
	f->ctx = test_ctx();
	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(f->ctx, CBL_LIM_MAX_FRAME,
	    SMALL_MAX));
	ATF_REQUIRE_EQ(0, cbl_family_register(f->ctx, &s_def, NULL, &f->fam));
	ATF_REQUIRE_EQ(0, cbl_loop_new(f->ctx, &f->loop));
	ATF_REQUIRE_EQ(0, cbl_listener_new(f->ctx, "sctp://127.0.0.1:0",
	    CBL_PLAINTEXT, &f->l));
	ATF_REQUIRE_EQ(0, cbl_listener_start(f->l, f->loop));
	ATF_REQUIRE_EQ(0, cbl_listener_addr(f->l, &ss, &len));
	memcpy(&f->sin, &ss, sizeof(f->sin));
	ATF_REQUIRE_EQ(0, pthread_create(&f->thr, NULL, sloop, f->loop));
}

static void
sfx_stop(struct sfx *f)
{

	cbl_loop_stop(f->loop);
	pthread_join(f->thr, NULL);
	cbl_listener_free(f->l);
	cbl_loop_free(f->loop);
	ATF_REQUIRE_EQ(0, cbl_family_unregister(f->fam));
	cbl_ctx_free(f->ctx);
}

static int
ssock(struct sfx *f)
{
	int fd, one = 1, buf = 4 * 1024 * 1024;

	ATF_REQUIRE((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) != -1);
	ATF_REQUIRE(setsockopt(fd, IPPROTO_SCTP, SCTP_RECVRCVINFO, &one,
	    sizeof(one)) == 0);
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
	ATF_REQUIRE(connect(fd, (struct sockaddr *)&f->sin,
	    sizeof(f->sin)) == 0);
	return (fd);
}

/* Send one frame as one SCTP message on SCTP stream "sid". */
static void
ssend(int fd, const void *buf, size_t len, uint16_t sid)
{
	struct sctp_sndinfo si = { .snd_sid = sid };
	struct iovec iov = { .iov_base = (void *)(uintptr_t)buf,
	    .iov_len = len };

	ATF_REQUIRE_EQ((ssize_t)len, sctp_sendv(fd, &iov, 1, NULL, 0, &si,
	    sizeof(si), SCTP_SENDV_SNDINFO, 0));
}

/* Receive one whole SCTP message, its SCTP stream in "sidp". */
static cbl_msg *
srecv(cbl_ctx *ctx, int fd, uint16_t *sidp)
{
	static unsigned char buf[SMALL_MAX];
	unsigned char cbuf[CMSG_SPACE(sizeof(struct sctp_rcvinfo))];
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	struct sctp_rcvinfo ri;
	struct cmsghdr *cm;
	struct msghdr mh;
	struct iovec iov;
	size_t have = 0;
	ssize_t n;
	cbl_msg *m;

	*sidp = UINT16_MAX;
	do {
		ATF_REQUIRE_EQ(1, poll(&pfd, 1, 5000));
		memset(&mh, 0, sizeof(mh));
		iov.iov_base = buf + have;
		iov.iov_len = sizeof(buf) - have;
		mh.msg_iov = &iov;
		mh.msg_iovlen = 1;
		mh.msg_control = cbuf;
		mh.msg_controllen = sizeof(cbuf);
		ATF_REQUIRE((n = recvmsg(fd, &mh, 0)) > 0);
		have += (size_t)n;
		for (cm = CMSG_FIRSTHDR(&mh); cm != NULL;
		    cm = CMSG_NXTHDR(&mh, cm))
			if (cm->cmsg_level == IPPROTO_SCTP &&
			    cm->cmsg_type == SCTP_RCVINFO) {
				memcpy(&ri, CMSG_DATA(cm), sizeof(ri));
				*sidp = ri.rcv_sid;
			}
	} while ((mh.msg_flags & MSG_EOR) == 0);
	ATF_REQUIRE_EQ(0, cbl_frame_decode(ctx, buf, have, NULL, &m));
	return (m);
}

/* An echo request whose body is { 1: bytes(n) }. */
static size_t
mkbig(unsigned char *buf, uint16_t fam, uint32_t seq, size_t n)
{
	size_t len = CBL_HDRLEN + 1 + 1 + 5 + n;

	(void)mkframe(buf, CBL_HDRLEN, fam, S_ECHO, CBL_F_REQUEST, seq, 0,
	    NULL);
	buf[4] = (unsigned char)(len >> 24);
	buf[5] = (unsigned char)(len >> 16);
	buf[6] = (unsigned char)(len >> 8);
	buf[7] = (unsigned char)len;
	buf[CBL_HDRLEN] = 0xA1;
	buf[CBL_HDRLEN + 1] = 0x01;
	buf[CBL_HDRLEN + 2] = 0x5A;		/* bytes, 32-bit length */
	buf[CBL_HDRLEN + 3] = (unsigned char)(n >> 24);
	buf[CBL_HDRLEN + 4] = (unsigned char)(n >> 16);
	buf[CBL_HDRLEN + 5] = (unsigned char)(n >> 8);
	buf[CBL_HDRLEN + 6] = (unsigned char)n;
	memset(buf + CBL_HDRLEN + 7, 0x5A, n);
	return (len);
}

ATF_TC_WITHOUT_HEAD(stream_mapping);
ATF_TC_BODY(stream_mapping, tc)
{
	unsigned char buf[256];
	struct sctp_status st;
	socklen_t slen = sizeof(st);
	uint16_t fam, sid, want;
	struct sfx f;
	cbl_msg *m;
	size_t len;
	int fd, data = 0;

	sfx_start(&f);
	fd = ssock(&f);
	fam = cbl_family_id(f.fam);
	memset(&st, 0, sizeof(st));
	ATF_REQUIRE(getsockopt(fd, IPPROTO_SCTP, SCTP_STATUS, &st,
	    &slen) == 0);
	ATF_REQUIRE(st.sstat_instrms >= 2);
	want = (uint16_t)(1 + 1 % (st.sstat_instrms - 1));

	/* Requests and responses use SCTP stream 0. */
	len = mkframe(buf, sizeof(buf), fam, S_ECHO, CBL_F_REQUEST, 1, 0,
	    "A1 01 18 2A");
	ssend(fd, buf, len, 0);
	m = srecv(f.ctx, fd, &sid);
	ATF_REQUIRE_EQ(0, sid);
	ATF_REQUIRE_EQ(1, cbl_msg_seq(m));
	cbl_msg_free(m);

	/* cblink stream 1 travels on its own SCTP stream. */
	len = mkframe(buf, sizeof(buf), fam, S_FEED,
	    CBL_F_REQUEST | CBL_F_S_OPEN, 2, 1, "A0");
	ssend(fd, buf, len, 0);
	for (;;) {
		m = srecv(f.ctx, fd, &sid);
		ATF_REQUIRE_EQ(1, cbl_msg_stream(m));
		ATF_REQUIRE_EQ_MSG(want, sid, "frame flags %#x on sid %u",
		    cbl_msg_flags(m), sid);
		if ((cbl_msg_flags(m) & CBL_F_S_DATA) != 0)
			data++;
		if ((cbl_msg_flags(m) & CBL_F_S_HCLOSE) != 0) {
			cbl_msg_free(m);
			break;
		}
		cbl_msg_free(m);
	}
	ATF_REQUIRE_EQ(FEED_ITEMS, data);
	close(fd);
	sfx_stop(&f);
}

ATF_TC_WITHOUT_HEAD(large_messages);
ATF_TC_BODY(large_messages, tc)
{
	unsigned char *buf;
	const void *p;
	size_t len, blen;
	uint16_t fam, sid;
	struct sfx f;
	cbl_msg *m;
	int fd;

	sfx_start(&f);
	fd = ssock(&f);
	fam = cbl_family_id(f.fam);
	ATF_REQUIRE((buf = malloc(2 * SMALL_MAX)) != NULL);

	/* Many SCTP chunks, reassembled into one frame. */
	len = mkbig(buf, fam, 1, 200000);
	ssend(fd, buf, len, 0);
	m = srecv(f.ctx, fd, &sid);
	ATF_REQUIRE_EQ(1, cbl_msg_seq(m));
	ATF_REQUIRE_EQ(0, cbl_attr_bytes(cbl_msg_attr(m, 1), &p, &blen));
	ATF_REQUIRE_EQ(200000, blen);
	cbl_msg_free(m);

	/* Over max_frame: dropped without buffering it whole. */
	len = mkbig(buf, fam, 2, SMALL_MAX + 1000);
	ssend(fd, buf, len, 0);

	/* The association is still usable. */
	len = mkbig(buf, fam, 3, 10);
	ssend(fd, buf, len, 0);
	m = srecv(f.ctx, fd, &sid);
	ATF_REQUIRE_EQ(3, cbl_msg_seq(m));
	cbl_msg_free(m);
	free(buf);
	close(fd);
	sfx_stop(&f);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, stream_mapping);
	ATF_TP_ADD_TC(tp, large_messages);
	return (atf_no_error());
}
