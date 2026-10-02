/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* Attribute building and reading. */

#include <errno.h>
#include <math.h>

#include "cbl_test.h"

/* Encode, then decode through the public frame API. */
static cbl_msg *
roundtrip(cbl_ctx *ctx, cbl_msg *msg)
{
	const void *frame;
	cbl_msg *rx;
	size_t len, used;
	int error;

	error = cbl_msg_encode(msg, &frame, &len);
	ATF_REQUIRE_MSG(error == 0, "encode %d: %s", error,
	    cbl_msg_errstr(msg) != NULL ? cbl_msg_errstr(msg) : "");
	error = cbl_frame_decode(ctx, frame, len, &used, &rx);
	ATF_REQUIRE_MSG(error == 0, "decode %d", error);
	ATF_REQUIRE_EQ(len, used);
	cbl_msg_free(msg);
	return (rx);
}

ATF_TC_WITHOUT_HEAD(scalars);
ATF_TC_BODY(scalars, tc)
{
	static const uint8_t blob[] = { 0, 1, 2, 0xff };
	cbl_ctx *ctx = test_ctx();
	const void *p;
	const char *s;
	cbl_msg *msg;
	uint64_t u;
	int64_t i;
	double d;
	size_t len;
	bool b;

	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, CBL_F_REQUEST, &msg));
	ATF_REQUIRE_EQ(0, cbl_put_uint(msg, 1, UINT64_MAX));
	ATF_REQUIRE_EQ(0, cbl_put_int(msg, 2, INT64_MIN));
	ATF_REQUIRE_EQ(0, cbl_put_int(msg, 3, 42));
	ATF_REQUIRE_EQ(0, cbl_put_bool(msg, 4, false));
	ATF_REQUIRE_EQ(0, cbl_put_flag(msg, 5));
	ATF_REQUIRE_EQ(0, cbl_put_str(msg, 6, "h\xc3\xa9llo"));
	ATF_REQUIRE_EQ(0, cbl_put_bytes(msg, 7, blob, sizeof(blob)));
	ATF_REQUIRE_EQ(0, cbl_put_double(msg, 8, 0.1));
	ATF_REQUIRE_EQ(0, cbl_put_double(msg, 9, 1.5));
	ATF_REQUIRE_EQ(0, cbl_put_null(msg, 10));
	ATF_REQUIRE_EQ(0, cbl_put_strn(msg, 11, "abcdef", 3));
	ATF_REQUIRE_EQ(0, cbl_put_double(msg, 12, INFINITY));
	ATF_REQUIRE_EQ(0, cbl_put_uint(msg, 65535, 7));
	msg = roundtrip(ctx, msg);

	ATF_REQUIRE_EQ(0, cbl_attr_uint(cbl_msg_attr(msg, 1), &u));
	ATF_REQUIRE_EQ(UINT64_MAX, u);
	ATF_REQUIRE_EQ(ERANGE, cbl_attr_int(cbl_msg_attr(msg, 1), &i));
	ATF_REQUIRE_EQ(0, cbl_attr_int(cbl_msg_attr(msg, 2), &i));
	ATF_REQUIRE_EQ(INT64_MIN, i);
	ATF_REQUIRE_EQ(ERANGE, cbl_attr_uint(cbl_msg_attr(msg, 2), &u));
	ATF_REQUIRE_EQ(0, cbl_attr_int(cbl_msg_attr(msg, 3), &i));
	ATF_REQUIRE_EQ(42, i);
	ATF_REQUIRE_EQ(CBL_K_UINT, cbl_attr_kind(cbl_msg_attr(msg, 3)));
	ATF_REQUIRE_EQ(0, cbl_attr_bool(cbl_msg_attr(msg, 4), &b));
	ATF_REQUIRE(!b);
	ATF_REQUIRE_EQ(0, cbl_attr_bool(cbl_msg_attr(msg, 5), &b));
	ATF_REQUIRE(b);
	ATF_REQUIRE_EQ(0, cbl_attr_str(msg, cbl_msg_attr(msg, 6), &s));
	ATF_REQUIRE_STREQ("h\xc3\xa9llo", s);
	ATF_REQUIRE_EQ(0, cbl_attr_bytes(cbl_msg_attr(msg, 7), &p, &len));
	ATF_REQUIRE_EQ(sizeof(blob), len);
	ATF_REQUIRE(memcmp(p, blob, len) == 0);
	ATF_REQUIRE_EQ(0, cbl_attr_double(cbl_msg_attr(msg, 8), &d));
	ATF_REQUIRE(d == 0.1);
	ATF_REQUIRE_EQ(0, cbl_attr_double(cbl_msg_attr(msg, 9), &d));
	ATF_REQUIRE(d == 1.5);
	ATF_REQUIRE_EQ(CBL_K_NULL, cbl_attr_kind(cbl_msg_attr(msg, 10)));
	ATF_REQUIRE_EQ(0, cbl_attr_str(msg, cbl_msg_attr(msg, 11), &s));
	ATF_REQUIRE_STREQ("abc", s);
	ATF_REQUIRE_EQ(0, cbl_attr_double(cbl_msg_attr(msg, 12), &d));
	ATF_REQUIRE(isinf(d));
	ATF_REQUIRE(cbl_msg_attr(msg, 65535) != NULL);
	ATF_REQUIRE(cbl_msg_attr(msg, 13) == NULL);
	ATF_REQUIRE(cbl_msg_attr(msg, 0) == NULL);
	/* Wrong-kind accessors. */
	ATF_REQUIRE_EQ(EINVAL, cbl_attr_bool(cbl_msg_attr(msg, 1), &b));
	ATF_REQUIRE_EQ(EINVAL, cbl_attr_str(msg, cbl_msg_attr(msg, 7), &s));
	ATF_REQUIRE_EQ(EINVAL, cbl_attr_uint(NULL, &u));
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

/* Nesting, arrays, and lookups in out-of-order maps. */
ATF_TC_WITHOUT_HEAD(nested);
ATF_TC_BODY(nested, tc)
{
	cbl_ctx *ctx = test_ctx();
	const cbl_attr *a, *n, *e;
	cbl_msg *msg;
	uint64_t u;
	int count;

	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, CBL_F_REQUEST, &msg));
	cbl_put_uint(msg, 9, 9);
	cbl_nest_start(msg, 3);
	cbl_put_uint(msg, 2, 22);
	cbl_put_uint(msg, 1, 11);
	cbl_nest_start(msg, 7);
	cbl_put_str(msg, 1, "deep");
	cbl_nest_end(msg);
	cbl_nest_end(msg);
	cbl_array_start(msg, 4);
	for (uint64_t i = 0; i < 3; i++)
		cbl_put_uint(msg, CBL_ELEM, i * 10);
	cbl_nest_start(msg, CBL_ELEM);
	cbl_put_uint(msg, 1, 1);
	cbl_nest_end(msg);
	cbl_array_end(msg);
	cbl_put_uint(msg, 1, 1);
	msg = roundtrip(ctx, msg);

	n = cbl_msg_attr(msg, 3);
	ATF_REQUIRE_EQ(CBL_K_NEST, cbl_attr_kind(n));
	ATF_REQUIRE_EQ(3, cbl_attr_count(n));
	ATF_REQUIRE_EQ(0, cbl_attr_uint(cbl_attr_get(n, 1), &u));
	ATF_REQUIRE_EQ(11, u);
	ATF_REQUIRE_EQ(0, cbl_attr_uint(cbl_attr_get(n, 2), &u));
	ATF_REQUIRE_EQ(22, u);
	e = cbl_attr_get(cbl_attr_get(n, 7), 1);
	ATF_REQUIRE_EQ(CBL_K_TEXT, cbl_attr_kind(e));

	a = cbl_msg_attr(msg, 4);
	ATF_REQUIRE_EQ(CBL_K_ARRAY, cbl_attr_kind(a));
	ATF_REQUIRE_EQ(4, cbl_attr_count(a));
	ATF_REQUIRE_EQ(0, cbl_attr_uint(cbl_attr_index(a, 2), &u));
	ATF_REQUIRE_EQ(20, u);
	ATF_REQUIRE_EQ(CBL_K_NEST, cbl_attr_kind(cbl_attr_index(a, 3)));
	ATF_REQUIRE(cbl_attr_index(a, 4) == NULL);
	ATF_REQUIRE_EQ(0, cbl_attr_type(cbl_attr_index(a, 0)));

	/* Iteration over the body is in key order. */
	count = 0;
	u = 0;
	for (e = cbl_attr_first(cbl_msg_body(msg)); e != NULL;
	    e = cbl_attr_next(e)) {
		ATF_REQUIRE(cbl_attr_type(e) > u);
		u = cbl_attr_type(e);
		count++;
	}
	ATF_REQUIRE_EQ(4, count);
	/* Array iteration. */
	count = 0;
	for (e = cbl_attr_first(a); e != NULL; e = cbl_attr_next(e))
		count++;
	ATF_REQUIRE_EQ(4, count);
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

/* Container heads are widened past 23, 255 and 65535 entries. */
ATF_TC_WITHOUT_HEAD(large_containers);
ATF_TC_BODY(large_containers, tc)
{
	static const uint32_t sizes[] = { 0, 1, 23, 24, 255, 256, 3000 };
	cbl_ctx *ctx = test_ctx();
	const cbl_attr *a;
	cbl_msg *msg;
	uint64_t u;

	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(ctx, CBL_LIM_MAX_ATTRS, 10000));
	for (size_t s = 0; s < nitems(sizes); s++) {
		ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, 0, &msg));
		cbl_nest_start(msg, 1);
		for (uint32_t i = 0; i < sizes[s]; i++)
			cbl_put_uint(msg, (uint16_t)(sizes[s] - i), i);
		cbl_nest_end(msg);
		cbl_array_start(msg, 2);
		for (uint32_t i = 0; i < sizes[s]; i++)
			cbl_put_uint(msg, CBL_ELEM, i);
		cbl_array_end(msg);
		msg = roundtrip(ctx, msg);
		a = cbl_msg_attr(msg, 1);
		ATF_REQUIRE_EQ(sizes[s], cbl_attr_count(a));
		for (uint32_t i = 0; i < sizes[s]; i++) {
			ATF_REQUIRE_EQ(0, cbl_attr_uint(cbl_attr_get(a,
			    (uint16_t)(sizes[s] - i)), &u));
			ATF_REQUIRE_EQ(i, u);
		}
		a = cbl_msg_attr(msg, 2);
		ATF_REQUIRE_EQ(sizes[s], cbl_attr_count(a));
		if (sizes[s] > 0) {
			cbl_attr_uint(cbl_attr_index(a, sizes[s] - 1), &u);
			ATF_REQUIRE_EQ(sizes[s] - 1, u);
		}
		cbl_msg_free(msg);
	}
	cbl_ctx_free(ctx);
}

/* Long strings use 1, 2 and 4 byte length heads. */
ATF_TC_WITHOUT_HEAD(long_strings);
ATF_TC_BODY(long_strings, tc)
{
	static const size_t sizes[] = { 0, 23, 24, 255, 256, 65535, 65536 };
	cbl_ctx *ctx = test_ctx();
	const char *s;
	cbl_msg *msg;
	char *buf;

	buf = malloc(65537);
	ATF_REQUIRE(buf != NULL);
	for (size_t i = 0; i < nitems(sizes); i++) {
		memset(buf, 'x', sizes[i]);
		buf[sizes[i]] = '\0';
		ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, 0, &msg));
		ATF_REQUIRE_EQ(0, cbl_put_str(msg, 1, buf));
		msg = roundtrip(ctx, msg);
		ATF_REQUIRE_EQ(0, cbl_attr_str(msg, cbl_msg_attr(msg, 1), &s));
		ATF_REQUIRE_EQ(sizes[i], strlen(s));
		cbl_msg_free(msg);
	}
	free(buf);
	cbl_ctx_free(ctx);
}

/* cbl_put_attr() copies a decoded subtree, dropping framework keys. */
ATF_TC_WITHOUT_HEAD(copy_attr);
ATF_TC_BODY(copy_attr, tc)
{
	cbl_ctx *ctx = test_ctx();
	const void *f1, *f2;
	cbl_msg *msg, *copy;
	size_t l1, l2;

	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, 0, &msg));
	cbl_nest_start(msg, 1);
	cbl_put_int(msg, 1, -5);
	cbl_put_str(msg, 2, "x");
	cbl_array_start(msg, 3);
	cbl_put_bytes(msg, CBL_ELEM, "ab", 2);
	cbl_put_double(msg, CBL_ELEM, 2.25);
	cbl_put_null(msg, CBL_ELEM);
	cbl_put_bool(msg, CBL_ELEM, true);
	cbl_array_end(msg);
	cbl_nest_end(msg);
	msg = roundtrip(ctx, msg);

	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, 0, &copy));
	ATF_REQUIRE_EQ(0, cbl_put_attr(copy, 1, cbl_msg_attr(msg, 1)));
	ATF_REQUIRE_EQ(0, cbl_msg_encode(copy, &f2, &l2));
	/* A received message encodes to its original frame. */
	ATF_REQUIRE_EQ(0, cbl_msg_encode(msg, &f1, &l1));
	ATF_REQUIRE_EQ(l1, l2);
	ATF_REQUIRE(memcmp(f1, f2, l1) == 0);
	cbl_msg_free(copy);
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

/* Builder errors are sticky and reported once at encode time. */
ATF_TC_WITHOUT_HEAD(builder_errors);
ATF_TC_BODY(builder_errors, tc)
{
	cbl_ctx *ctx = test_ctx();
	cbl_msg *msg;

	/* Duplicate key, then further puts are no-ops. */
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, 0, &msg));
	ATF_REQUIRE_EQ(0, cbl_put_uint(msg, 3, 1));
	ATF_REQUIRE_EQ(0, cbl_put_uint(msg, 1, 1));
	ATF_REQUIRE_EQ(EEXIST, cbl_put_uint(msg, 3, 2));
	ATF_REQUIRE_EQ(EEXIST, cbl_put_uint(msg, 4, 2));
	ATF_REQUIRE_EQ(EEXIST, cbl_msg_encode(msg, NULL, NULL));
	ATF_REQUIRE(cbl_msg_errstr(msg) != NULL);
	cbl_msg_free(msg);

	/* Type 0 in a map, non-ELEM in an array. */
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, 0, &msg));
	ATF_REQUIRE_EQ(EINVAL, cbl_put_uint(msg, 0, 1));
	cbl_msg_free(msg);
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, 0, &msg));
	cbl_array_start(msg, 1);
	ATF_REQUIRE_EQ(EINVAL, cbl_put_uint(msg, 2, 1));
	cbl_msg_free(msg);

	/* Unbalanced. */
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, 0, &msg));
	cbl_nest_start(msg, 1);
	ATF_REQUIRE_EQ(EINVAL, cbl_msg_encode(msg, NULL, NULL));
	cbl_msg_free(msg);
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, 0, &msg));
	ATF_REQUIRE_EQ(EINVAL, cbl_nest_end(msg));
	cbl_msg_free(msg);
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, 0, &msg));
	cbl_nest_start(msg, 1);
	ATF_REQUIRE_EQ(EINVAL, cbl_array_end(msg));
	cbl_msg_free(msg);

	/* Bad text. */
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, 0, &msg));
	ATF_REQUIRE_EQ(EINVAL, cbl_put_strn(msg, 1, "a\0b", 3));
	cbl_msg_free(msg);
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, 0, &msg));
	ATF_REQUIRE_EQ(EINVAL, cbl_put_str(msg, 1, "\xc0\x80"));
	cbl_msg_free(msg);

	/* Read-only after encode. */
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, 0, &msg));
	ATF_REQUIRE_EQ(0, cbl_msg_encode(msg, NULL, NULL));
	ATF_REQUIRE_EQ(EBUSY, cbl_put_uint(msg, 1, 1));
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

ATF_TC_WITHOUT_HEAD(builder_limits);
ATF_TC_BODY(builder_limits, tc)
{
	cbl_ctx *ctx = test_ctx();
	static char big[8192];
	cbl_msg *msg;
	int error;

	/* Depth: the body map is level 1. */
	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(ctx, CBL_LIM_MAX_DEPTH, 3));
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, 0, &msg));
	ATF_REQUIRE_EQ(0, cbl_nest_start(msg, 1));
	ATF_REQUIRE_EQ(0, cbl_nest_start(msg, 1));
	ATF_REQUIRE_EQ(ELOOP, cbl_nest_start(msg, 1));
	cbl_msg_free(msg);

	/* Attribute count. */
	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(ctx, CBL_LIM_MAX_ATTRS, 16));
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, 0, &msg));
	error = 0;
	for (uint16_t i = 1; i <= 17 && error == 0; i++)
		error = cbl_put_uint(msg, i, i);
	ATF_REQUIRE_EQ(E2BIG, error);
	cbl_msg_free(msg);

	/* Frame size. */
	ATF_REQUIRE_EQ(0, cbl_ctx_set_limit(ctx, CBL_LIM_MAX_FRAME, 4096));
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, 0, &msg));
	ATF_REQUIRE_EQ(EMSGSIZE, cbl_put_bytes(msg, 1, big, sizeof(big)));
	cbl_msg_free(msg);
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, 0, &msg));
	ATF_REQUIRE_EQ(0, cbl_put_bytes(msg, 1, big, 4096 - 24 - 5));
	ATF_REQUIRE_EQ(0, cbl_msg_encode(msg, NULL, NULL));
	ATF_REQUIRE_EQ(4096, cbl_msg_len(msg));
	cbl_msg_free(msg);

	/* Limit validation. */
	ATF_REQUIRE_EQ(EINVAL, cbl_ctx_set_limit(ctx, CBL_LIM_MAX_FRAME, 1));
	ATF_REQUIRE_EQ(EINVAL, cbl_ctx_set_limit(ctx, CBL_LIM_MAX_DEPTH, 65));
	ATF_REQUIRE_EQ(EINVAL, cbl_ctx_set_limit(ctx, CBL_LIM__COUNT, 1));
	cbl_ctx_free(ctx);
}

/* Extended ack: path with array indices, missing type, cookie. */
ATF_TC_WITHOUT_HEAD(extended_ack);
ATF_TC_BODY(extended_ack, tc)
{
	struct cbl_path_elem path[] = {
		{ .v = 3 }, { .v = 2, .index = true }, { .v = 7 },
	}, got[3];
	cbl_ctx *ctx = test_ctx();
	char longmsg[CBL_ERRMSG_MAX + 100];
	const void *ck;
	cbl_msg *msg;
	size_t cklen;

	memset(longmsg, 'e', sizeof(longmsg) - 1);
	longmsg[sizeof(longmsg) - 1] = '\0';
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, CBL_F_ERROR, &msg));
	ATF_REQUIRE_EQ(0, cbl_msg_put_error(msg, EINVAL, longmsg, path, 3, 9));
	ATF_REQUIRE_EQ(0, cbl_msg_put_cookie(msg, "ck", 2));
	msg = roundtrip(ctx, msg);
	ATF_REQUIRE_EQ(EINVAL, cbl_msg_err_code(msg));
	ATF_REQUIRE_EQ(CBL_ERRMSG_MAX, strlen(cbl_msg_err_str(msg)));
	ATF_REQUIRE_EQ(3, cbl_msg_err_path(msg, got, 3));
	ATF_REQUIRE(got[0].v == 3 && !got[0].index);
	ATF_REQUIRE(got[1].v == 2 && got[1].index);
	ATF_REQUIRE(got[2].v == 7 && !got[2].index);
	ATF_REQUIRE_EQ(9, cbl_msg_err_miss_type(msg));
	ATF_REQUIRE_EQ(0, cbl_msg_err_cookie(msg, &ck, &cklen));
	ATF_REQUIRE(cklen == 2 && memcmp(ck, "ck", 2) == 0);
	cbl_msg_free(msg);

	/* An ack may carry a warning; err_code stays 0. */
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 5, 1, CBL_F_ACK, &msg));
	ATF_REQUIRE_EQ(0, cbl_msg_put_error(msg, 0, "warning", NULL, 0, -1));
	msg = roundtrip(ctx, msg);
	ATF_REQUIRE_EQ(0, cbl_msg_err_code(msg));
	ATF_REQUIRE_STREQ("warning", cbl_msg_err_str(msg));
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, scalars);
	ATF_TP_ADD_TC(tp, nested);
	ATF_TP_ADD_TC(tp, large_containers);
	ATF_TP_ADD_TC(tp, long_strings);
	ATF_TP_ADD_TC(tp, copy_attr);
	ATF_TP_ADD_TC(tp, builder_errors);
	ATF_TP_ADD_TC(tp, builder_limits);
	ATF_TP_ADD_TC(tp, extended_ack);
	return (atf_no_error());
}
