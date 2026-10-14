/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* Hostile input: every malformation must be rejected without crashing. */

#include <errno.h>

#include "cbl_test.h"
#include "cbl_impl.h"	/* the decoder's tree, as the library reads it */

static int
decode_body(cbl_ctx *ctx, const char *bodyhex, cbl_msg **msgp)
{
	unsigned char buf[8192];
	size_t len;

	len = mkframe(buf, sizeof(buf), 5, 1, CBL_F_REQUEST, 1, 0, bodyhex);
	return (cbl_frame_decode(ctx, buf, len, NULL, msgp));
}

static void
require_body_error(cbl_ctx *ctx, const char *bodyhex, int want)
{
	cbl_msg *msg;
	int error;

	error = decode_body(ctx, bodyhex, &msg);
	ATF_CHECK_MSG(error == want, "body %s: got %d, want %d", bodyhex,
	    error, want);
	if (error == 0)
		cbl_msg_free(msg);
}

ATF_TC_WITHOUT_HEAD(bad_header);
ATF_TC_BODY(bad_header, tc)
{
	cbl_ctx *ctx = test_ctx();
	unsigned char buf[64];
	cbl_msg *msg;
	size_t len;

	len = mkframe(buf, sizeof(buf), 1, 1, CBL_F_REQUEST, 1, 0, "A0");
	buf[0] = 0x16;		/* a TLS handshake record */
	ATF_REQUIRE_EQ(EPROTO, cbl_frame_decode(ctx, buf, len, NULL, &msg));
	buf[0] = 0xCB;
	buf[1] = 'G';
	ATF_REQUIRE_EQ(EPROTO, cbl_frame_decode(ctx, buf, len, NULL, &msg));
	buf[1] = 0x4C;
	/* Version 1, cblink's first, and one to come. */
	buf[2] = 1;
	ATF_REQUIRE_EQ(EPROTONOSUPPORT,
	    cbl_frame_decode(ctx, buf, len, NULL, &msg));
	buf[2] = CBL_PROTO_VERSION + 1;
	ATF_REQUIRE_EQ(EPROTONOSUPPORT,
	    cbl_frame_decode(ctx, buf, len, NULL, &msg));
	buf[2] = CBL_PROTO_VERSION;
	static const uint8_t bad_hdrlen[] = { 0, 20, 23, 25, 26, 68, 255 };
	for (size_t i = 0; i < nitems(bad_hdrlen); i++) {
		buf[3] = bad_hdrlen[i];
		ATF_CHECK_EQ(EPROTO,
		    cbl_frame_decode(ctx, buf, len, NULL, &msg));
	}
	buf[3] = 24;
	ATF_REQUIRE_EQ(0, cbl_frame_decode(ctx, buf, len, NULL, &msg));
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

ATF_TC_WITHOUT_HEAD(bad_length);
ATF_TC_BODY(bad_length, tc)
{
	cbl_ctx *ctx = test_ctx();
	unsigned char buf[64];
	cbl_msg *msg;
	size_t len;

	len = mkframe(buf, sizeof(buf), 1, 1, CBL_F_REQUEST, 1, 0, "A0");
	/* Shorter than the header. */
	buf[7] = 23;
	ATF_REQUIRE_EQ(EMSGSIZE, cbl_frame_decode(ctx, buf, len, NULL, &msg));
	/* Larger than max_frame (1 MiB + 1), and the maximum. */
	buf[4] = 0x00; buf[5] = 0x10; buf[6] = 0x00; buf[7] = 0x01;
	ATF_REQUIRE_EQ(EMSGSIZE, cbl_frame_decode(ctx, buf, len, NULL, &msg));
	buf[4] = buf[5] = buf[6] = buf[7] = 0xff;
	ATF_REQUIRE_EQ(EMSGSIZE, cbl_frame_decode(ctx, buf, len, NULL, &msg));
	/* Exactly max_frame, but not all here yet. */
	buf[4] = 0x00; buf[5] = 0x10; buf[6] = 0x00; buf[7] = 0x00;
	ATF_REQUIRE_EQ(EAGAIN, cbl_frame_decode(ctx, buf, len, NULL, &msg));
	cbl_ctx_free(ctx);
}

ATF_TC_WITHOUT_HEAD(truncated);
ATF_TC_BODY(truncated, tc)
{
	cbl_ctx *ctx = test_ctx();
	unsigned char buf[256], cut[256];
	cbl_msg *msg;
	size_t len, used;

	len = mkframe(buf, sizeof(buf), 1, 1, CBL_F_REQUEST, 1, 0,
	    "A3 01 63 66 6F 6F 02 82 01 A1 01 1A 00 01 00 00"
	    "03 5A 00 00 00 02 AB CD");
	/* Any short buffer asks for more data. */
	for (size_t n = 0; n < len; n++)
		ATF_CHECK_EQ(EAGAIN,
		    cbl_frame_decode(ctx, buf, n, &used, &msg));
	/* A frame whose length cuts the CBOR short is malformed. */
	for (size_t n = CBL_HDRLEN + 1; n < len; n++) {
		memcpy(cut, buf, n);
		cut[4] = cut[5] = cut[6] = 0;
		cut[7] = (unsigned char)n;
		ATF_CHECK_EQ(EBADMSG,
		    cbl_frame_decode(ctx, cut, n, NULL, &msg));
	}
	ATF_REQUIRE_EQ(0, cbl_frame_decode(ctx, buf, len, NULL, &msg));
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

ATF_TC_WITHOUT_HEAD(invalid_cbor);
ATF_TC_BODY(invalid_cbor, tc)
{
	cbl_ctx *ctx = test_ctx();

	require_body_error(ctx, "FC", EBADMSG);		/* reserved */
	require_body_error(ctx, "A1 01 1C", EBADMSG);	/* reserved AI */
	require_body_error(ctx, "A1 01 F0", EBADMSG);	/* unassigned simple */
	require_body_error(ctx, "A1 01 F8 20", EBADMSG);
	require_body_error(ctx, "A1 01 01 00", EBADMSG);	/* trailing */
	require_body_error(ctx, "A0 A0", EBADMSG);	/* two roots */
	require_body_error(ctx, "A2 01 01", EBADMSG);	/* short map */
	/* Container larger than the body: refused before allocating. */
	require_body_error(ctx, "A1 01 99 0F A0 01", EBADMSG);
	/* String length past the end. */
	require_body_error(ctx, "A1 01 7B 7F FF FF FF FF FF FF FF", EBADMSG);
	cbl_ctx_free(ctx);
}

ATF_TC_WITHOUT_HEAD(profile_violations);
ATF_TC_BODY(profile_violations, tc)
{
	cbl_ctx *ctx = test_ctx();

	require_body_error(ctx, "01", EPROTO);		/* not a map */
	require_body_error(ctx, "80", EPROTO);
	require_body_error(ctx, "BF 01 01 FF", EPROTO);	/* indefinite map */
	require_body_error(ctx, "A1 01 9F 01 FF", EPROTO);
	require_body_error(ctx, "A1 01 7F 61 61 FF", EPROTO);
	require_body_error(ctx, "A1 01 5F 41 61 FF", EPROTO);
	require_body_error(ctx, "A1 01 FF", EPROTO);	/* stray break */
	require_body_error(ctx, "A1 01 C1 01", EPROTO);	/* tag */
	require_body_error(ctx, "A1 01 F7", EPROTO);	/* undefined */
	require_body_error(ctx, "A1 61 61 01", EPROTO);	/* text key */
	require_body_error(ctx, "A1 F9 3C 00 01", EPROTO);	/* float key */
	require_body_error(ctx, "A1 80 01", EPROTO);	/* array key */
	require_body_error(ctx, "A1 F5 01", EPROTO);	/* bool key */
	require_body_error(ctx, "A2 01 01 01 02", EPROTO);	/* duplicate */
	require_body_error(ctx, "A1 01 A2 20 01 20 02", EPROTO);
	require_body_error(ctx, "A1 01 62 C3 28", EPROTO);	/* bad UTF-8 */
	/* Overlong NUL. */
	require_body_error(ctx, "A1 01 62 C0 80", EPROTO);
	require_body_error(ctx, "A1 01 63 ED A0 80", EPROTO);	/* surrogate */
	/* Above U+10FFFF. */
	require_body_error(ctx, "A1 01 64 F4 90 80 80", EPROTO);
	cbl_ctx_free(ctx);
}

/* Builds a body nested "levels" deep: {1: {1: ... 0}}. */
static void
nested_hex(char *out, size_t max, int levels, bool arrays)
{
	size_t n = 0;

	n += snprintf(out + n, max - n, "A1 01 ");
	for (int i = 1; i < levels; i++)
		n += snprintf(out + n, max - n, arrays ? "81 " : "A1 01 ");
	snprintf(out + n, max - n, "00");
}

ATF_TC_WITHOUT_HEAD(excessive_nesting);
ATF_TC_BODY(excessive_nesting, tc)
{
	cbl_ctx *ctx = test_ctx();
	char hex[1024];
	cbl_msg *msg;

	/* Default max_depth is 16; the body map counts as one. */
	nested_hex(hex, sizeof(hex), 16, false);
	ATF_REQUIRE_EQ(0, decode_body(ctx, hex, &msg));
	cbl_msg_free(msg);
	nested_hex(hex, sizeof(hex), 17, false);
	require_body_error(ctx, hex, ELOOP);
	nested_hex(hex, sizeof(hex), 17, true);
	require_body_error(ctx, hex, ELOOP);
	nested_hex(hex, sizeof(hex), 200, true);
	require_body_error(ctx, hex, ELOOP);
	cbl_ctx_free(ctx);
}

ATF_TC_WITHOUT_HEAD(too_many_attrs);
ATF_TC_BODY(too_many_attrs, tc)
{
	cbl_ctx *ctx = test_ctx();
	char hex[1024];
	size_t n = 0;

	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(ctx, CBL_LIM_MAX_ATTRS, 16));
	n += snprintf(hex, sizeof(hex), "B1 ");		/* 17 pairs */
	for (int i = 1; i <= 17; i++)
		n += snprintf(hex + n, sizeof(hex) - n, "%02X 00 ", i);
	require_body_error(ctx, hex, E2BIG);
	/* Values are counted recursively, including array elements. */
	require_body_error(ctx,
	    "A2 01 88 00 00 00 00 00 00 00 00 02 88 00 00 00 00 00 00 00 00",
	    E2BIG);
	/* A huge declared count is refused before anything is allocated. */
	require_body_error(ctx, "A1 01 9B FF FF FF FF FF FF FF FF", E2BIG);
	require_body_error(ctx, "BB 00 00 00 01 00 00 00 00", E2BIG);
	cbl_ctx_free(ctx);
}

/* Section 5.4: unknown attributes are ignored, framework keys hidden. */
/*
 * Top-level keys: SIDs from 1 to 2^63 - 1 are items; 0, negative keys
 * and keys beyond are taken and never found.
 */
ATF_TC_WITHOUT_HEAD(unknown_attrs_ignored);
ATF_TC_BODY(unknown_attrs_ignored, tc)
{
	cbl_ctx *ctx = test_ctx();
	cbl_msg *msg;
	uint64_t v;

	/*
	 * {-1 - 2^64: 0, -100: 0, -50: 0, 0: 0, 1: 1, 7: 7,
	 *  70000: 0, 2^64-1: 0, 2: neg-big}
	 */
	ATF_REQUIRE_EQ(0, decode_body(ctx,
	    "A9 3B FF FF FF FF FF FF FF FF 00 38 63 00 38 31 00 00 00"
	    "01 01 07 07 1A 00 01 11 70 00 1B FF FF FF FF FF FF FF FF 00"
	    "02 3B FF FF FF FF FF FF FF FF", &msg));
	ATF_REQUIRE(t_get_uint(msg, 1, &v) && v == 1);
	ATF_REQUIRE(t_get_uint(msg, 7, &v) && v == 7);
	ATF_REQUIRE(t_get_uint(msg, 70000, &v) && v == 0);
	/* 2: a negative integer beyond int64_t, as it was sent. */
	ATF_REQUIRE_EQ(0, cbl_msg_sid_raw(msg, 2, &(const void *){ 0 },
	    &(size_t){ 0 }));
	ATF_REQUIRE_EQ(EINVAL, cbl_msg_sid_raw(msg, UINT64_MAX,
	    &(const void *){ 0 }, &(size_t){ 0 }));
	ATF_REQUIRE_EQ(EINVAL, cbl_msg_sid_raw(msg, 0, &(const void *){ 0 },
	    &(size_t){ 0 }));
	/* Not an ERROR frame: no error code even with a -1 key. */
	ATF_REQUIRE_EQ(0, cbl_msg_err_code(msg));
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

ATF_TC_WITHOUT_HEAD(error_frame_sanity);
ATF_TC_BODY(error_frame_sanity, tc)
{
	cbl_ctx *ctx = test_ctx();
	unsigned char buf[128];
	cbl_msg *msg;
	size_t len;

	/* ERROR without CODE. */
	len = mkframe(buf, sizeof(buf), 1, 1, CBL_F_ERROR, 1, 0, "A0");
	ATF_REQUIRE_EQ(0, cbl_frame_decode(ctx, buf, len, NULL, &msg));
	ATF_REQUIRE_EQ(EPROTO, cbl_msg_err_code(msg));
	cbl_msg_free(msg);
	/* CODE of the wrong kind, MSG with NUL, PATH malformed. */
	len = mkframe(buf, sizeof(buf), 1, 1, CBL_F_ERROR, 1, 0,
	    "A3 20 61 61 21 63 61 00 62 22 81 61 61");
	ATF_REQUIRE_EQ(0, cbl_frame_decode(ctx, buf, len, NULL, &msg));
	ATF_REQUIRE_EQ(EPROTO, cbl_msg_err_code(msg));
	ATF_REQUIRE(cbl_msg_err_str(msg) == NULL);
	ATF_REQUIRE_EQ(0, cbl_msg_err_path(msg, NULL, 0));
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

/* Deterministic random mutation of a valid frame; must never crash. */
/* The body's first value, as the decoder took it, its tag kept. */
static const cbl_attr *
yang_value(cbl_ctx *ctx, const char *bodyhex, cbl_msg **msgp)
{
	const cbl_attr *body;

	ATF_REQUIRE_EQ_MSG(0, decode_body(ctx, bodyhex, msgp), "body %s",
	    bodyhex);
	body = cbl_msg_body(*msgp);
	return (body != NULL && body->count > 0 ? &body->child[0] : NULL);
}

ATF_TC_WITHOUT_HEAD(yang_tags);
ATF_TC_BODY(yang_tags, tc)
{
	static const char *const accepted[] = {
		"A1 01 C4 82 21 19 0C 5D",	/* 4: decimal64 31.65 */
		"A1 01 D8 2B 64 72 65 61 64",	/* 43: bits, by name */
		"A1 01 D8 2C 63 75 70 30",	/* 44: enumeration */
		"A1 01 D8 2D 19 07 14",		/* 45: identityref SID */
		"A1 01 D8 2D 61 78",		/* 45: identityref name */
		"A1 01 D8 2E 19 05 DE",		/* 46: instance-id SID */
		"A1 01 D8 2E 82 19 05 DE 63 65 6D 30",	/* with a key */
		"A1 01 D8 2F 19 05 DC",		/* 47: absolute SID */
	};
	static const uint64_t tags[] = { 4, 43, 44, 45, 45, 46, 46, 47 };
	cbl_ctx *ctx = test_ctx();
	const cbl_attr *a;
	uint32_t flags;
	cbl_msg *msg;

	/* Version 2 takes them as they are, no flag asked (D-1). */
	ATF_REQUIRE_EQ(0, cbl_ctx_get_flags(ctx, &flags));
	ATF_REQUIRE_EQ(0, flags);
	ATF_REQUIRE_EQ(EINVAL, cbl_ctx_set_flags(ctx, 0x2));

	for (size_t i = 0; i < nitems(accepted); i++) {
		a = yang_value(ctx, accepted[i], &msg);
		ATF_REQUIRE(a != NULL);
		ATF_CHECK_EQ_MSG(tags[i], a->tag, "%s", accepted[i]);
		cbl_msg_free(msg);
	}
	/* An untagged value says so; a nested one keeps its tag. */
	a = yang_value(ctx, "A2 01 01 02 82 D8 2F 01 02", &msg);
	ATF_CHECK_EQ(0, a[0].tag);
	ATF_CHECK_EQ(0, a[1].tag);
	ATF_REQUIRE_EQ(2, a[1].count);
	ATF_CHECK_EQ(47, a[1].child[0].tag);
	ATF_CHECK_EQ(0, a[1].child[1].tag);
	cbl_msg_free(msg);

	/* Bits in a union are their names (RFC 9254 section 6.7). */
	require_body_error(ctx, "A1 01 D8 2B 42 05 01", EPROTO);
	require_body_error(ctx, "A1 01 D8 2B 82 01 02", EPROTO);
	/* Every other tag is still refused. */
	require_body_error(ctx, "A1 01 C0 61 78", EPROTO);	/* 0 */
	require_body_error(ctx, "A1 01 C1 01", EPROTO);		/* 1 */
	require_body_error(ctx, "A1 01 C2 41 01", EPROTO);	/* 2: bignum */
	require_body_error(ctx, "A1 01 C5 82 01 01", EPROTO);	/* 5 */
	require_body_error(ctx, "A1 01 D8 2A 01", EPROTO);	/* 42 */
	require_body_error(ctx, "A1 01 D8 30 01", EPROTO);	/* 48 */
	require_body_error(ctx, "A1 01 D9 01 2F 01", EPROTO);	/* 303 */
	require_body_error(ctx, "A1 01 D9 D9 F7 01", EPROTO);	/* 55799 */
	require_body_error(ctx, "A1 01 DB 00 00 00 01 00 00 00 2F 01",
	    EPROTO);					/* 2^32 + 47 */
	/* Not on the body, a key, or twice; nor on the wrong kind. */
	require_body_error(ctx, "D8 2F A1 01 01", EPROTO);
	require_body_error(ctx, "A1 D8 2F 01 01", EPROTO);
	require_body_error(ctx, "A1 01 D8 2F D8 2F 01", EPROTO);
	require_body_error(ctx, "A1 01 C4 83 21 01 01", EPROTO);
	require_body_error(ctx, "A1 01 C4 19 0C 5D", EPROTO);
	require_body_error(ctx, "A1 01 D8 2C 01", EPROTO);
	require_body_error(ctx, "A1 01 D8 2F 61 78", EPROTO);
	require_body_error(ctx, "A1 01 D8 2F 20", EPROTO);
	require_body_error(ctx, "A1 01 D8 2D A0", EPROTO);
	require_body_error(ctx, "A1 01 D8 2B F6", EPROTO);
	/* A tag with nothing after it. */
	require_body_error(ctx, "A1 01 D8 2F", EBADMSG);
	require_body_error(ctx, "A1 01 01 D8 2F", EBADMSG);
	cbl_ctx_free(ctx);
}

ATF_TC_WITHOUT_HEAD(mutations);
ATF_TC_BODY(mutations, tc)
{
	cbl_ctx *ctx = test_ctx();
	unsigned char orig[256], buf[256];
	uint32_t seed = 12345;
	cbl_msg *msg;
	size_t len;

	len = mkframe(orig, sizeof(orig), 1, 1, CBL_F_REQUEST, 1, 0,
	    "A4 01 63 66 6F 6F 02 82 01 A1 01 1A 00 01 00 00"
	    "03 5A 00 00 00 02 AB CD 04 A2 20 01 21 F9 3C 00");
	for (int iter = 0; iter < 200000; iter++) {
		memcpy(buf, orig, len);
		for (int k = 0; k < 1 + iter % 4; k++) {
			seed = seed * 1103515245 + 12345;
			buf[CBL_HDRLEN + (seed >> 8) % (len - CBL_HDRLEN)] =
			    (unsigned char)(seed >> 16);
		}
		if (cbl_frame_decode(ctx, buf, len, NULL, &msg) == 0) {
			/* Look up what decoded. */
			for (uint64_t sid = 1; sid <= 4; sid++)
				(void)cbl_msg_sid_raw(msg, sid,
				    &(const void *){ 0 }, &(size_t){ 0 });
			cbl_msg_free(msg);
		}
	}
	cbl_ctx_free(ctx);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, bad_header);
	ATF_TP_ADD_TC(tp, bad_length);
	ATF_TP_ADD_TC(tp, truncated);
	ATF_TP_ADD_TC(tp, invalid_cbor);
	ATF_TP_ADD_TC(tp, profile_violations);
	ATF_TP_ADD_TC(tp, excessive_nesting);
	ATF_TP_ADD_TC(tp, too_many_attrs);
	ATF_TP_ADD_TC(tp, unknown_attrs_ignored);
	ATF_TP_ADD_TC(tp, error_frame_sanity);
	ATF_TP_ADD_TC(tp, yang_tags);
	ATF_TP_ADD_TC(tp, mutations);
	return (atf_no_error());
}
