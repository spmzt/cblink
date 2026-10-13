/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Version 2 bodies (PLAN-SDN-YANG 1.7.2): one map whose top-level keys
 * are SIDs, past 65535 and to 2^63 - 1, the values YANG-CBOR with their
 * keys SID deltas, negative ones too; decoded in two passes under the
 * limits as every body is, each value's bytes found again exactly.
 */

#include <errno.h>
#include <string.h>

#include "cbl_test.h"
#include "cbl_schema.h"

#define	SID	(UINT64_C(1) << 40)

/* Encode msg, decode it with ctx's limits: the error, the message. */
static int
roundtrip(cbl_ctx *ctx, cbl_msg *msg, cbl_msg **outp)
{
	const void *frame;
	size_t len, used;

	ATF_REQUIRE_EQ(0, cbl_msg_encode(msg, &frame, &len));
	*outp = NULL;
	return (cbl_frame_decode(ctx, frame, len, &used, outp));
}

ATF_TC_WITHOUT_HEAD(sid_keys);
ATF_TC_BODY(sid_keys, tc)
{
	/* {-3: 1, 70000: "x", 2: [4(-2, 2531)]} */
	static const uint8_t v1[] = { 0xa3, 0x22, 0x01, 0x1a, 0x00, 0x01,
	    0x11, 0x70, 0x61, 'x', 0x02, 0x81, 0xc4, 0x82, 0x21, 0x19, 0x09,
	    0xe3 };
	static const uint8_t v2[] = { 0xf6 };
	cbl_ctx *ctx = test_ctx();
	cbl_msg *msg, *got;
	const void *p;
	size_t len;

	ATF_REQUIRE_EQ(0, cbl_ctx_set_flags(ctx, CBL_CTX_YANG_TAGS));
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 1, 1, CBL_F_REQUEST, &msg));
	ATF_REQUIRE_EQ(0, cbl_msg_put_sid_raw(msg, 1700, v2, sizeof(v2)));
	ATF_REQUIRE_EQ(0, cbl_msg_put_sid_raw(msg, SID + 5, v1, sizeof(v1)));
	ATF_REQUIRE_EQ(0, roundtrip(ctx, msg, &got));
	ATF_REQUIRE_EQ(0, cbl_msg_sid_raw(got, SID + 5, &p, &len));
	ATF_CHECK_EQ(sizeof(v1), len);
	ATF_CHECK(len == sizeof(v1) && memcmp(p, v1, len) == 0);
	ATF_REQUIRE_EQ(0, cbl_msg_sid_raw(got, 1700, &p, &len));
	ATF_CHECK(len == 1 && *(const uint8_t *)p == 0xf6);
	ATF_CHECK_EQ(ENOENT, cbl_msg_sid_raw(got, SID + 6, &p, &len));
	cbl_msg_free(got);
	cbl_msg_free(msg);

	/* 0 is no SID, 2^63 none either; a SID keys the top only. */
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 1, 1, CBL_F_REQUEST, &msg));
	ATF_CHECK_EQ(EINVAL, cbl_msg_put_sid_raw(msg, 0, v2, sizeof(v2)));
	cbl_msg_free(msg);
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 1, 1, CBL_F_REQUEST, &msg));
	ATF_CHECK_EQ(EINVAL, cbl_msg_put_sid_raw(msg, UINT64_C(1) << 63, v2,
	    sizeof(v2)));
	cbl_msg_free(msg);
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 1, 1, CBL_F_REQUEST, &msg));
	ATF_REQUIRE_EQ(0, cbl_nest_start(msg, 1));
	ATF_CHECK_EQ(EINVAL, cbl_msg_put_sid_raw(msg, SID, v2, sizeof(v2)));
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

/* Keys out of order: sorted, and each value's bytes still its own. */
ATF_TC_WITHOUT_HEAD(out_of_order);
ATF_TC_BODY(out_of_order, tc)
{
	cbl_ctx *ctx = test_ctx();
	unsigned char buf[128];
	cbl_msg *msg;
	const void *p;
	size_t len, flen;

	/* {1800: {2: "b"}, 1700: {1: "a", -1: 7}, 1750: [1, 2]} */
	flen = mkframe(buf, sizeof(buf), 1, 1, CBL_F_REQUEST, 1, 0,
	    "A3 19 07 08 A1 02 61 62 19 06 A4 A2 01 61 61 20 07"
	    "19 06 D6 82 01 02");
	ATF_REQUIRE_EQ(0, cbl_frame_decode(ctx, buf, flen, NULL, &msg));
	ATF_REQUIRE_EQ(0, cbl_msg_sid_raw(msg, 1700, &p, &len));
	ATF_CHECK(len == 6 && memcmp(p, "\xa2\x01\x61\x61\x20\x07", 6) == 0);
	ATF_REQUIRE_EQ(0, cbl_msg_sid_raw(msg, 1800, &p, &len));
	ATF_CHECK(len == 4 && memcmp(p, "\xa1\x02\x61\x62", 4) == 0);
	ATF_REQUIRE_EQ(0, cbl_msg_sid_raw(msg, 1750, &p, &len));
	ATF_CHECK(len == 3 && memcmp(p, "\x82\x01\x02", 3) == 0);
	cbl_msg_free(msg);
	/* A key twice, apart: refused once sorted. */
	flen = mkframe(buf, sizeof(buf), 1, 1, CBL_F_REQUEST, 1, 0,
	    "A3 19 06 A4 01 19 07 08 02 19 06 A4 03");
	ATF_CHECK_EQ(EPROTO, cbl_frame_decode(ctx, buf, flen, NULL, &msg));
	cbl_ctx_free(ctx);
}

/* The limits hold for SID-keyed bodies as for any. */
ATF_TC_WITHOUT_HEAD(limits);
ATF_TC_BODY(limits, tc)
{
	static uint8_t big[5000];
	uint8_t deep[20], wide[24];
	cbl_ctx *ctx = test_ctx();
	cbl_msg *msg, *got;
	size_t i;

	/* Depth: {1: {1: ... 1}}, nine maps, the body's own the tenth. */
	for (i = 0; i < 9; i++) {
		deep[2 * i] = 0xa1;
		deep[2 * i + 1] = 0x01;
	}
	deep[18] = 0x01;
	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(ctx, CBL_LIM_MAX_DEPTH, 8));
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 1, 1, CBL_F_REQUEST, &msg));
	ATF_REQUIRE_EQ(0, cbl_msg_put_sid_raw(msg, SID, deep, 19));
	ATF_CHECK_EQ(ELOOP, roundtrip(ctx, msg, &got));
	cbl_msg_free(got);
	cbl_msg_free(msg);
	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(ctx, CBL_LIM_MAX_DEPTH, 32));

	/* Values: an array of twenty, against a limit of sixteen. */
	wide[0] = 0x94;
	for (i = 1; i <= 20; i++)
		wide[i] = (uint8_t)i;
	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(ctx, CBL_LIM_MAX_ATTRS, 16));
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 1, 1, CBL_F_REQUEST, &msg));
	ATF_REQUIRE_EQ(0, cbl_msg_put_sid_raw(msg, SID, wide, 21));
	ATF_CHECK_EQ(E2BIG, roundtrip(ctx, msg, &got));
	cbl_msg_free(got);
	cbl_msg_free(msg);
	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(ctx, CBL_LIM_MAX_ATTRS, 1024));

	/* The frame: a value past it is refused as it is put. */
	memset(big, 0x01, sizeof(big));
	big[0] = 0x59;			/* bytes, a two-byte length */
	big[1] = (sizeof(big) - 3) >> 8;
	big[2] = (sizeof(big) - 3) & 0xff;
	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(ctx, CBL_LIM_MAX_FRAME, 4096));
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 1, 1, CBL_F_REQUEST, &msg));
	ATF_CHECK_EQ(EMSGSIZE, cbl_msg_put_sid_raw(msg, SID, big,
	    sizeof(big)));
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, sid_keys);
	ATF_TP_ADD_TC(tp, out_of_order);
	ATF_TP_ADD_TC(tp, limits);
	return (atf_no_error());
}
