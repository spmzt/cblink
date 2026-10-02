/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* Hostile input: every malformation must be rejected without crashing. */

#include <errno.h>

#include "cbl_test.h"

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
	buf[2] = 2;
	ATF_REQUIRE_EQ(EPROTONOSUPPORT,
	    cbl_frame_decode(ctx, buf, len, NULL, &msg));
	buf[2] = 1;
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
ATF_TC_WITHOUT_HEAD(unknown_attrs_ignored);
ATF_TC_BODY(unknown_attrs_ignored, tc)
{
	cbl_ctx *ctx = test_ctx();
	const cbl_attr *a;
	cbl_msg *msg;
	int64_t i;
	int n = 0;

	/*
	 * {-1 - 2^64: 0, -100: 0, -50: 0, 0: 0, 1: 1, 7: 7,
	 *  70000: 0, 2^64-1: 0, 2: neg-big}
	 */
	ATF_REQUIRE_EQ(0, decode_body(ctx,
	    "A9 3B FF FF FF FF FF FF FF FF 00 38 63 00 38 31 00 00 00"
	    "01 01 07 07 1A 00 01 11 70 00 1B FF FF FF FF FF FF FF FF 00"
	    "02 3B FF FF FF FF FF FF FF FF", &msg));
	for (a = cbl_attr_first(cbl_msg_body(msg)); a != NULL;
	    a = cbl_attr_next(a)) {
		ATF_REQUIRE(cbl_attr_type(a) >= 1);
		n++;
	}
	ATF_REQUIRE_EQ(3, n);
	ATF_REQUIRE(cbl_msg_attr(msg, 1) != NULL);
	ATF_REQUIRE(cbl_msg_attr(msg, 7) != NULL);
	ATF_REQUIRE_EQ(CBL_K_INT, cbl_attr_kind(cbl_msg_attr(msg, 2)));
	ATF_REQUIRE_EQ(ERANGE, cbl_attr_int(cbl_msg_attr(msg, 2), &i));
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
			/* Walk whatever decoded. */
			for (const cbl_attr *a = cbl_attr_first(
			    cbl_msg_body(msg)); a != NULL; a = cbl_attr_next(a))
				(void)cbl_attr_count(a);
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
	ATF_TP_ADD_TC(tp, mutations);
	return (atf_no_error());
}
