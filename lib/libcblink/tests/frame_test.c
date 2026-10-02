/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Header encoding and decoding, flag validation, and every hex dump in
 * docs/WIRE-FORMAT.md, byte for byte.
 */

#include <errno.h>

#include "cbl_test.h"

static cbl_msg *
decode_hex(cbl_ctx *ctx, const char *hex)
{
	unsigned char buf[4096];
	cbl_msg *msg;
	size_t len, used;
	int error;

	len = hex2bin(hex, buf, sizeof(buf));
	error = cbl_frame_decode(ctx, buf, len, &used, &msg);
	ATF_REQUIRE_MSG(error == 0, "decode: %d", error);
	ATF_REQUIRE_EQ(len, used);
	return (msg);
}

#define	ERR_FRAME \
	"CB 4C 01 18 00 00 00 2B 00 11 00 01 00 00 00 20" \
	"00 00 00 01 00 00 00 00" \
	"A3 20 02 21 6B 6E 6F 20 73 75 63 68 20 6B 65 79 22 81 01"

ATF_TC_WITHOUT_HEAD(wire_error_frame);
ATF_TC_BODY(wire_error_frame, tc)
{
	struct cbl_path_elem path[] = { { .v = 1 } }, got[4];
	cbl_ctx *ctx = test_ctx();
	cbl_msg *msg;

	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 17, 1, CBL_F_ERROR, &msg));
	ATF_REQUIRE_EQ(0, cbl_msg_set_seq(msg, 1));
	ATF_REQUIRE_EQ(0, cbl_msg_put_error(msg, ENOENT, "no such key",
	    path, 1, -1));
	require_frame(msg, ERR_FRAME);
	cbl_msg_free(msg);

	msg = decode_hex(ctx, ERR_FRAME);
	ATF_REQUIRE_EQ(ENOENT, cbl_msg_err_code(msg));
	ATF_REQUIRE_STREQ("no such key", cbl_msg_err_str(msg));
	ATF_REQUIRE_EQ(1, cbl_msg_err_path(msg, got, 4));
	ATF_REQUIRE_EQ(1, got[0].v);
	ATF_REQUIRE(!got[0].index);
	ATF_REQUIRE_EQ(-1, cbl_msg_err_miss_type(msg));
	/* Framework keys are invisible to attribute iteration. */
	ATF_REQUIRE(cbl_attr_first(cbl_msg_body(msg)) == NULL);
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

ATF_TC_WITHOUT_HEAD(wire_getfamily);
ATF_TC_BODY(wire_getfamily, tc)
{
	cbl_ctx *ctx = test_ctx();
	cbl_msg *msg;

	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 0, 1, CBL_F_REQUEST, &msg));
	cbl_msg_set_seq(msg, 7);
	cbl_put_str(msg, 2, "kv");
	require_frame(msg,
	    "CB 4C 01 18 00 00 00 1D 00 00 00 01 00 00 00 01"
	    "00 00 00 07 00 00 00 00 A1 02 62 6B 76");
	cbl_msg_free(msg);

	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 0, 1, 0, &msg));
	cbl_msg_set_seq(msg, 7);
	cbl_put_uint(msg, 1, 17);
	cbl_put_str(msg, 2, "kv");
	cbl_put_uint(msg, 3, 1);
	cbl_array_start(msg, 4);
	cbl_nest_start(msg, CBL_ELEM);
	cbl_put_uint(msg, 1, 1);
	cbl_put_str(msg, 2, "get");
	cbl_put_uint(msg, 3, 1);
	cbl_nest_end(msg);
	cbl_array_end(msg);
	cbl_array_start(msg, 5);
	cbl_nest_start(msg, CBL_ELEM);
	cbl_put_uint(msg, 1, 2);
	cbl_put_str(msg, 2, "changes");
	cbl_put_uint(msg, 3, 0);
	cbl_nest_end(msg);
	cbl_array_end(msg);
	require_frame(msg,
	    "CB 4C 01 18 00 00 00 3D 00 00 00 01 00 00 00 00"
	    "00 00 00 07 00 00 00 00"
	    "A5 01 11 02 62 6B 76 03 01"
	    "04 81 A3 01 01 02 63 67 65 74 03 01"
	    "05 81 A3 01 02 02 67 63 68 61 6E 67 65 73 03 00");
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

ATF_TC_WITHOUT_HEAD(wire_do_and_ack);
ATF_TC_BODY(wire_do_and_ack, tc)
{
	cbl_ctx *ctx = test_ctx();
	cbl_msg *msg;

	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 17, 1,
	    CBL_F_REQUEST | CBL_F_ACK, &msg));
	cbl_msg_set_seq(msg, 1);
	cbl_put_str(msg, 1, "foo");
	require_frame(msg,
	    "CB 4C 01 18 00 00 00 1E 00 11 00 01 00 00 00 03"
	    "00 00 00 01 00 00 00 00 A1 01 63 66 6F 6F");
	cbl_msg_free(msg);

	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 17, 1, CBL_F_ACK, &msg));
	cbl_msg_set_seq(msg, 1);
	require_frame(msg,
	    "CB 4C 01 18 00 00 00 18 00 11 00 01 00 00 00 02"
	    "00 00 00 01 00 00 00 00");
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

ATF_TC_WITHOUT_HEAD(wire_notify);
ATF_TC_BODY(wire_notify, tc)
{
	cbl_ctx *ctx = test_ctx();
	cbl_msg *msg;

	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 17, 4, CBL_F_NOTIFY, &msg));
	cbl_msg_set_stream(msg, 2);
	cbl_put_str(msg, 1, "k");
	require_frame(msg,
	    "CB 4C 01 18 00 00 00 1C 00 11 00 04 00 00 00 40"
	    "00 00 00 00 00 00 00 02 A1 01 61 6B");
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

/* Section 8.4: stream frames decode, framework keys stay hidden. */
ATF_TC_WITHOUT_HEAD(wire_stream_frames);
ATF_TC_BODY(wire_stream_frames, tc)
{
	static const char *frames[] = {
		"CB 4C 01 18 00 00 00 26 00 11 00 03 00 01 00 01"
		"00 00 00 08 00 00 00 01"
		"A2 25 1A 00 01 00 00 01 65 75 73 65 72 2F",
		"CB 4C 01 18 00 00 00 1D 00 11 00 03 00 01 00 00"
		"00 00 00 08 00 00 00 01 A1 25 19 80 00",
		"CB 4C 01 18 00 00 00 21 00 11 00 03 00 02 00 00"
		"00 00 00 00 00 00 00 01 A1 01 66 75 73 65 72 2F 61",
		"CB 4C 01 18 00 00 00 1C 00 11 00 03 00 20 00 00"
		"00 00 00 00 00 00 00 01 A1 25 18 21",
		"CB 4C 01 18 00 00 00 18 00 11 00 03 00 04 00 00"
		"00 00 00 00 00 00 00 01",
	};
	static const uint32_t flags[] = {
		CBL_F_REQUEST | CBL_F_S_OPEN, CBL_F_S_OPEN, CBL_F_S_DATA,
		CBL_F_S_CREDIT, CBL_F_S_HCLOSE,
	};
	cbl_ctx *ctx = test_ctx();
	const cbl_attr *a;
	const char *s;
	cbl_msg *msg;

	for (size_t i = 0; i < nitems(frames); i++) {
		msg = decode_hex(ctx, frames[i]);
		ATF_REQUIRE_EQ(flags[i], cbl_msg_flags(msg));
		ATF_REQUIRE_EQ(1, cbl_msg_stream(msg));
		ATF_REQUIRE_EQ(17, cbl_msg_family(msg));
		ATF_REQUIRE_EQ(3, cbl_msg_cmd(msg));
		if (i == 0) {
			a = cbl_attr_first(cbl_msg_body(msg));
			ATF_REQUIRE(a != NULL);
			ATF_REQUIRE_EQ(1, cbl_attr_type(a));
			ATF_REQUIRE_EQ(0, cbl_attr_str(msg, a, &s));
			ATF_REQUIRE_STREQ("user/", s);
			ATF_REQUIRE(cbl_attr_next(a) == NULL);
		}
		cbl_msg_free(msg);
	}
	cbl_ctx_free(ctx);
}

ATF_TC_WITHOUT_HEAD(header_fields);
ATF_TC_BODY(header_fields, tc)
{
	cbl_ctx *ctx = test_ctx();
	unsigned char buf[64];
	cbl_msg *msg;
	size_t len;

	len = mkframe(buf, sizeof(buf), 0xfffe, 0xabcd,
	    CBL_F_MULTI | CBL_F_DONE, 0xdeadbeef, 0, NULL);
	ATF_REQUIRE_EQ(0, cbl_frame_decode(ctx, buf, len, NULL, &msg));
	ATF_REQUIRE_EQ(0xfffe, cbl_msg_family(msg));
	ATF_REQUIRE_EQ(0xabcd, cbl_msg_cmd(msg));
	ATF_REQUIRE_EQ(CBL_F_MULTI | CBL_F_DONE, cbl_msg_flags(msg));
	ATF_REQUIRE_EQ(0xdeadbeef, cbl_msg_seq(msg));
	ATF_REQUIRE_EQ(CBL_HDRLEN, cbl_msg_len(msg));
	ATF_REQUIRE_EQ(0, cbl_attr_count(cbl_msg_body(msg)));
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

/* hdrlen > 24: extension bytes are skipped (section 2). */
ATF_TC_WITHOUT_HEAD(header_extension);
ATF_TC_BODY(header_extension, tc)
{
	cbl_ctx *ctx = test_ctx();
	unsigned char buf[64];
	cbl_msg *msg;

	hex2bin("CB 4C 01 20 00 00 00 23 00 11 00 01 00 00 00 00"
	    "00 00 00 05 00 00 00 00 EE EE EE EE EE EE EE EE"
	    "A1 01 01", buf, sizeof(buf));
	ATF_REQUIRE_EQ(0, cbl_frame_decode(ctx, buf, 35, NULL, &msg));
	ATF_REQUIRE(cbl_msg_attr(msg, 1) != NULL);
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

ATF_TC_WITHOUT_HEAD(flag_combinations);
ATF_TC_BODY(flag_combinations, tc)
{
	static const struct {
		uint32_t	flags;
		uint32_t	stream;
		bool		ok;
	} t[] = {
		{ CBL_F_REQUEST, 0, true },
		{ CBL_F_REQUEST | CBL_F_ACK, 0, true },
		{ CBL_F_REQUEST | CBL_F_DUMP, 0, true },
		{ CBL_F_REQUEST | CBL_F_DUMP | CBL_F_ACK, 0, true },
		{ 0, 0, true },
		{ CBL_F_ACK, 0, true },
		{ CBL_F_MULTI, 0, true },
		{ CBL_F_MULTI | CBL_F_DONE, 0, true },
		{ CBL_F_ERROR, 0, true },
		{ CBL_F_ERROR | CBL_F_MULTI | CBL_F_DONE, 0, true },
		{ CBL_F_ERROR | CBL_F_S_OPEN, 3, true },
		{ CBL_F_NOTIFY, 2, true },
		{ CBL_F_REQUEST | CBL_F_S_OPEN, 1, true },
		{ CBL_F_REQUEST | CBL_F_S_OPEN | CBL_F_S_DATA |
		    CBL_F_S_HCLOSE, 1, true },
		{ CBL_F_S_OPEN, 1, true },
		{ CBL_F_S_DATA, 1, true },
		{ CBL_F_S_DATA | CBL_F_S_HCLOSE, 1, true },
		{ CBL_F_S_HCLOSE, 1, true },
		{ CBL_F_S_CLOSE, 1, true },
		{ CBL_F_S_RESET, 1, true },
		{ CBL_F_S_CREDIT, 1, true },
		/* Invalid. */
		{ CBL_F_DONE, 0, false },
		{ CBL_F_ERROR | CBL_F_MULTI, 0, false },
		{ CBL_F_ACK | CBL_F_MULTI, 0, false },
		{ CBL_F_DUMP, 0, false },
		{ CBL_F_REQUEST | CBL_F_MULTI, 0, false },
		{ CBL_F_REQUEST | CBL_F_ERROR, 0, false },
		{ CBL_F_REQUEST | CBL_F_NOTIFY, 0, false },
		{ CBL_F_REQUEST, 1, false },
		{ CBL_F_NOTIFY, 0, false },
		{ CBL_F_NOTIFY | CBL_F_ACK, 2, false },
		{ CBL_F_REQUEST | CBL_F_S_DATA, 1, false },
		{ CBL_F_REQUEST | CBL_F_S_OPEN, 0, false },
		{ CBL_F_REQUEST | CBL_F_S_OPEN | CBL_F_ACK, 1, false },
		{ CBL_F_S_DATA, 0, false },
		{ CBL_F_S_CLOSE | CBL_F_S_RESET, 1, false },
		{ CBL_F_S_CREDIT | CBL_F_S_DATA, 1, false },
		{ CBL_F_S_DATA | CBL_F_MULTI, 1, false },
		{ CBL_F_ERROR, 1, false },
		{ 0, 1, false },
		{ 0x00000080, 0, false },
		{ 0x00400000, 0, false },
		{ 0x80000000, 0, false },
	};
	cbl_ctx *ctx = test_ctx();
	unsigned char buf[64];
	cbl_msg *msg;
	size_t len;
	int error;

	for (size_t i = 0; i < nitems(t); i++) {
		len = mkframe(buf, sizeof(buf), 1, 1, t[i].flags, 1,
		    t[i].stream, NULL);
		error = cbl_frame_decode(ctx, buf, len, NULL, &msg);
		ATF_CHECK_MSG((error == 0) == t[i].ok,
		    "flags %#x stream %u: error %d", t[i].flags,
		    t[i].stream, error);
		if (error == 0)
			cbl_msg_free(msg);
		else
			ATF_CHECK_EQ(EINVAL, error);
	}
	cbl_ctx_free(ctx);
}

/* The builder refuses to encode an invalid kind. */
ATF_TC_WITHOUT_HEAD(encode_invalid_flags);
ATF_TC_BODY(encode_invalid_flags, tc)
{
	cbl_ctx *ctx = test_ctx();
	cbl_msg *msg;

	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 1, 1, CBL_F_DONE, &msg));
	ATF_REQUIRE_EQ(EINVAL, cbl_msg_encode(msg, NULL, NULL));
	ATF_REQUIRE_EQ(0, cbl_msg_set_flags(msg, CBL_F_MULTI | CBL_F_DONE));
	ATF_REQUIRE_EQ(0, cbl_msg_encode(msg, NULL, NULL));
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

/* Several frames back to back: "used" lets a reader walk them. */
ATF_TC_WITHOUT_HEAD(frame_sequence);
ATF_TC_BODY(frame_sequence, tc)
{
	cbl_ctx *ctx = test_ctx();
	unsigned char buf[256];
	size_t len = 0, off = 0, used;
	cbl_msg *msg;
	int n = 0;

	for (uint32_t i = 1; i <= 3; i++)
		len += mkframe(buf + len, sizeof(buf) - len, 1, 1,
		    CBL_F_REQUEST, i, 0, "A1 01 01");
	while (off < len) {
		ATF_REQUIRE_EQ(0, cbl_frame_decode(ctx, buf + off, len - off,
		    &used, &msg));
		ATF_REQUIRE_EQ((uint32_t)++n, cbl_msg_seq(msg));
		cbl_msg_free(msg);
		off += used;
	}
	ATF_REQUIRE_EQ(3, n);
	/* A partial frame asks for more data. */
	ATF_REQUIRE_EQ(EAGAIN, cbl_frame_decode(ctx, buf, 10, &used, &msg));
	ATF_REQUIRE_EQ(EAGAIN, cbl_frame_decode(ctx, buf, 26, &used, &msg));
	cbl_ctx_free(ctx);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, wire_error_frame);
	ATF_TP_ADD_TC(tp, wire_getfamily);
	ATF_TP_ADD_TC(tp, wire_do_and_ack);
	ATF_TP_ADD_TC(tp, wire_notify);
	ATF_TP_ADD_TC(tp, wire_stream_frames);
	ATF_TP_ADD_TC(tp, header_fields);
	ATF_TP_ADD_TC(tp, header_extension);
	ATF_TP_ADD_TC(tp, flag_combinations);
	ATF_TP_ADD_TC(tp, encode_invalid_flags);
	ATF_TP_ADD_TC(tp, frame_sequence);
	return (atf_no_error());
}
