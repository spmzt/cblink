/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* Declarative policies and parsers. */

#include <errno.h>
#include <stddef.h>

#include "cbl_test.h"

static cbl_msg *
encode_decode(cbl_ctx *ctx, cbl_msg *msg)
{
	const void *f;
	cbl_msg *rx;
	size_t len;

	ATF_REQUIRE_EQ(0, cbl_msg_encode(msg, &f, &len));
	ATF_REQUIRE_EQ(0, cbl_frame_decode(ctx, f, len, NULL, &rx));
	cbl_msg_free(msg);
	return (rx);
}

enum { A_NAME = 1, A_PORT, A_TAGS, A_INNER, A_MODE, A_PERM, A_DELTA,
    A_ON, A_BLOB, A_EVEN };
enum { I_X = 1, I_Y };

static int
must_be_even(const cbl_attr *a, const void *arg __unused)
{
	uint64_t v;

	return (cbl_attr_uint(a, &v) != 0 || v % 2 != 0 ? EDOM : 0);
}

static const uint64_t mode_vals[] = { 1, 2, 4 };
static const struct cbl_enum mode_enum = { mode_vals, 3 };

static const struct cbl_policy inner_pol[] = {
	{ .type = I_X, .kind = CBL_K_UINT, .flags = CBL_PF_REQUIRED },
	{ .type = I_Y, .kind = CBL_K_TEXT },
};
CBL_POLICY_SET(inner_set, inner_pol);

static const struct cbl_policy top_pol[] = {
	{ .type = A_NAME, .kind = CBL_K_TEXT,
	  .flags = CBL_PF_REQUIRED | CBL_PF_RANGE, .len = { 1, 8 } },
	{ .type = A_PORT, .kind = CBL_K_UINT, .flags = CBL_PF_RANGE,
	  .u = { 1, 65535 } },
	{ .type = A_TAGS, .kind = CBL_K_TEXT,
	  .flags = CBL_PF_MULTI | CBL_PF_RANGE, .min_count = 1,
	  .max_count = 3, .len = { 1, 4 } },
	{ .type = A_INNER, .kind = CBL_K_NEST, .flags = CBL_PF_MULTI,
	  .nested = &inner_set },
	{ .type = A_MODE, .kind = CBL_K_UINT, .values = &mode_enum },
	{ .type = A_PERM, .kind = CBL_K_UINT, .flags = CBL_PF_MASK,
	  .u = { 0, 0x7 } },
	{ .type = A_DELTA, .kind = CBL_K_INT, .flags = CBL_PF_RANGE,
	  .i = { -10, 10 } },
	{ .type = A_ON, .kind = CBL_K_FLAG },
	{ .type = A_BLOB, .kind = CBL_K_BYTES, .flags = CBL_PF_RANGE,
	  .len = { 4, 4 } },
	{ .type = A_EVEN, .kind = CBL_K_UINT, .validate = must_be_even },
};
CBL_POLICY_SET(top_set, top_pol);

/* Build a valid message; "mut" breaks one aspect of it. */
static cbl_msg *
build(cbl_ctx *ctx, int mut)
{
	cbl_msg *m;

	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 1, 1, CBL_F_REQUEST, &m));
	if (mut != 1)
		cbl_put_str(m, A_NAME, mut == 2 ? "toolongname" : "srv");
	cbl_put_uint(m, A_PORT, mut == 3 ? 70000 : 443);
	cbl_array_start(m, A_TAGS);
	cbl_put_str(m, CBL_ELEM, "a");
	cbl_put_str(m, CBL_ELEM, mut == 4 ? "abcde" : "b");
	if (mut == 5) {
		cbl_put_str(m, CBL_ELEM, "c");
		cbl_put_str(m, CBL_ELEM, "d");
	}
	cbl_array_end(m);
	cbl_array_start(m, A_INNER);
	cbl_nest_start(m, CBL_ELEM);
	cbl_put_uint(m, I_X, 1);
	cbl_nest_end(m);
	cbl_nest_start(m, CBL_ELEM);
	if (mut != 6)
		cbl_put_uint(m, I_X, 2);
	cbl_put_str(m, I_Y, "y");
	cbl_put_uint(m, 77, 77);	/* unknown: ignored */
	cbl_nest_end(m);
	cbl_array_end(m);
	cbl_put_uint(m, A_MODE, mut == 7 ? 3 : 4);
	cbl_put_uint(m, A_PERM, mut == 8 ? 0x9 : 0x5);
	cbl_put_int(m, A_DELTA, mut == 9 ? -11 : -10);
	if (mut == 10)
		cbl_put_bool(m, A_ON, false);
	else
		cbl_put_flag(m, A_ON);
	cbl_put_bytes(m, A_BLOB, "abcd", mut == 11 ? 3 : 4);
	cbl_put_uint(m, A_EVEN, mut == 12 ? 3 : 2);
	if (mut == 13)
		cbl_put_str(m, A_PORT + 100, "unknown attrs are fine");
	return (encode_decode(ctx, m));
}

ATF_TC_WITHOUT_HEAD(validate);
ATF_TC_BODY(validate, tc)
{
	static const struct {
		int		 mut;
		int		 error;
		size_t		 pathlen;
		uint32_t	 path[3];
		int		 miss;
	} t[] = {
		{ 0, 0, 0, { 0 }, -1 },
		{ 13, 0, 0, { 0 }, -1 },
		{ 1, EINVAL, 0, { 0 }, A_NAME },
		{ 2, ERANGE, 1, { A_NAME }, -1 },
		{ 3, ERANGE, 1, { A_PORT }, -1 },
		{ 4, ERANGE, 2, { A_TAGS, 1 }, -1 },
		{ 5, ERANGE, 1, { A_TAGS }, -1 },
		{ 6, EINVAL, 2, { A_INNER, 1 }, I_X },
		{ 7, EINVAL, 1, { A_MODE }, -1 },
		{ 8, EINVAL, 1, { A_PERM }, -1 },
		{ 9, ERANGE, 1, { A_DELTA }, -1 },
		{ 10, EINVAL, 1, { A_ON }, -1 },
		{ 11, ERANGE, 1, { A_BLOB }, -1 },
		{ 12, EDOM, 1, { A_EVEN }, -1 },
	};
	cbl_ctx *ctx = test_ctx();
	struct cbl_verr ve;
	cbl_msg *m;
	int error;

	ATF_REQUIRE_EQ(0, cbl_policy_set_check(&top_set));
	for (size_t i = 0; i < nitems(t); i++) {
		m = build(ctx, t[i].mut);
		error = cbl_validate(cbl_msg_body(m), &top_set, &ve);
		ATF_CHECK_EQ_MSG(t[i].error, error, "mut %d: %d", t[i].mut,
		    error);
		if (error != 0) {
			ATF_CHECK(ve.msg != NULL);
			ATF_CHECK_EQ_MSG(t[i].pathlen, ve.pathlen, "mut %d",
			    t[i].mut);
			for (size_t j = 0; j < t[i].pathlen && j < ve.pathlen;
			    j++)
				ATF_CHECK_EQ(t[i].path[j], ve.path[j].v);
			if (t[i].pathlen == 2)
				ATF_CHECK(ve.path[1].index);
			ATF_CHECK_EQ(t[i].miss, ve.miss_type);
		}
		cbl_msg_free(m);
	}
	cbl_ctx_free(ctx);
}

ATF_TC_WITHOUT_HEAD(policy_check);
ATF_TC_BODY(policy_check, tc)
{
	static const struct cbl_policy unsorted[] = {
		{ .type = 2, .kind = CBL_K_UINT },
		{ .type = 1, .kind = CBL_K_UINT },
	};
	static const struct cbl_policy badrange[] = {
		{ .type = 1, .kind = CBL_K_UINT, .flags = CBL_PF_RANGE,
		  .u = { 5, 1 } },
	};
	static const struct cbl_policy zero[] = {
		{ .type = 0, .kind = CBL_K_UINT },
	};
	CBL_POLICY_SET(s1, unsorted);
	CBL_POLICY_SET(s2, badrange);
	CBL_POLICY_SET(s3, zero);

	ATF_REQUIRE_EQ(EINVAL, cbl_policy_set_check(&s1));
	ATF_REQUIRE_EQ(EINVAL, cbl_policy_set_check(&s2));
	ATF_REQUIRE_EQ(EINVAL, cbl_policy_set_check(&s3));
	ATF_REQUIRE_EQ(0, cbl_policy_set_check(NULL));
}

/* Parsers. */
struct inner {
	uint8_t		 x;
	const char	*y;
};

struct top {
	const char	*name;
	uint16_t	 port;
	struct cbl_array tags;		/* const char * */
	struct cbl_array inner;		/* struct inner */
	uint32_t	 mode;
	int8_t		 delta;
	bool		 on;
	struct cbl_bytes blob;
	struct inner	*first;
	const cbl_attr	*raw;
};

#define	_OUT(f)	offsetof(struct inner, f)
static const struct cbl_attr_parser inner_np[] = {
	{ .type = I_X, .off = _OUT(x), .cb = cbl_get_u8 },
	{ .type = I_Y, .off = _OUT(y), .cb = cbl_get_str },
};
#undef _OUT
CBL_DECLARE_PARSER(inner_parser, struct inner, inner_np, NULL);

static const struct cbl_array_desc tags_desc = {
	.cb = cbl_get_str, .elem_size = sizeof(const char *) };
static const struct cbl_array_desc inner_desc = {
	.cb = cbl_get_nested, .arg = &inner_parser,
	.elem_size = sizeof(struct inner) };

static int
top_post(cbl_msg *msg __unused, void *target)
{
	struct top *t = target;

	return (t->name == NULL ? ENOENT : 0);
}

#define	_OUT(f)	offsetof(struct top, f)
static const struct cbl_attr_parser top_np[] = {
	{ .type = A_NAME, .off = _OUT(name), .cb = cbl_get_str },
	{ .type = A_PORT, .off = _OUT(port), .cb = cbl_get_u16 },
	{ .type = A_TAGS, .off = _OUT(tags), .cb = cbl_get_array,
	  .arg = &tags_desc },
	{ .type = A_INNER, .off = _OUT(inner), .cb = cbl_get_array,
	  .arg = &inner_desc },
	{ .type = A_MODE, .off = _OUT(mode), .cb = cbl_get_u32 },
	{ .type = A_DELTA, .off = _OUT(delta), .cb = cbl_get_s8 },
	{ .type = A_ON, .off = _OUT(on), .cb = cbl_get_flag },
	{ .type = A_BLOB, .off = _OUT(blob), .cb = cbl_get_bytes },
	{ .type = A_EVEN, .off = _OUT(raw), .cb = cbl_get_attr },
};
#undef _OUT
CBL_DECLARE_PARSER(top_parser, struct top, top_np, top_post);

ATF_TC_WITHOUT_HEAD(parse);
ATF_TC_BODY(parse, tc)
{
	cbl_ctx *ctx = test_ctx();
	struct inner *in;
	struct top t;
	cbl_msg *m;
	uint64_t v;

	ATF_REQUIRE_EQ(0, cbl_parser_check(&top_parser));
	ATF_REQUIRE_EQ(0, cbl_parser_check(&inner_parser));
	m = build(ctx, 13);
	memset(&t, 0, sizeof(t));
	ATF_REQUIRE_EQ(0, cbl_parse(m, &top_parser, &t));
	ATF_REQUIRE_STREQ("srv", t.name);
	ATF_REQUIRE_EQ(443, t.port);
	ATF_REQUIRE_EQ(2, t.tags.n);
	ATF_REQUIRE_STREQ("b", ((const char **)t.tags.v)[1]);
	ATF_REQUIRE_EQ(2, t.inner.n);
	in = t.inner.v;
	ATF_REQUIRE_EQ(1, in[0].x);
	ATF_REQUIRE(in[0].y == NULL);
	ATF_REQUIRE_EQ(2, in[1].x);
	ATF_REQUIRE_STREQ("y", in[1].y);
	ATF_REQUIRE_EQ(4, t.mode);
	ATF_REQUIRE_EQ(-10, t.delta);
	ATF_REQUIRE(t.on);
	ATF_REQUIRE_EQ(4, t.blob.len);
	ATF_REQUIRE_EQ(0, cbl_attr_uint(t.raw, &v));
	ATF_REQUIRE_EQ(2, v);

	/* Nested pointer allocated from the arena. */
	ATF_REQUIRE_EQ(0, cbl_get_nested_ptr(m, cbl_attr_index(
	    cbl_msg_attr(m, A_INNER), 1), &inner_parser, &t.first));
	ATF_REQUIRE_EQ(2, t.first->x);
	cbl_msg_free(m);

	/* Narrowing: 443 does not fit a u8; the post callback can fail. */
	{
		static const struct cbl_attr_parser narrow_np[] = {
			{ .type = A_PORT, .off = 0, .cb = cbl_get_u8 },
		};
		CBL_DECLARE_PARSER(narrow, uint8_t, narrow_np, NULL);
		uint8_t u8;

		m = build(ctx, 0);
		ATF_REQUIRE_EQ(ERANGE, cbl_parse(m, &narrow, &u8));
		cbl_msg_free(m);
	}
	m = build(ctx, 1);
	memset(&t, 0, sizeof(t));
	ATF_REQUIRE_EQ(ENOENT, cbl_parse(m, &top_parser, &t));
	cbl_msg_free(m);
	cbl_ctx_free(ctx);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, validate);
	ATF_TP_ADD_TC(tp, policy_check);
	ATF_TP_ADD_TC(tp, parse);
	return (atf_no_error());
}
