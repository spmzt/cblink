/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The body of wire version 2, before libcblink speaks it: YANG data
 * encoded as CBOR with SIDs (RFC 9254), written here by hand with
 * libcbor and read back by SID deltas.  A key at the top of the body is
 * an absolute SID; a key further in is the difference between the
 * child's SID and its parent's, and may be negative; the entries of a
 * list are relative to the list's SID.
 *
 * The SID table is hand-written: ietf-interfaces' "interfaces" container
 * at 1500 as in RFC 9595's initial allocation, the rest numbered for
 * this test only.  "local-index" stands for a leaf that another module
 * augments into an interface from a lower SID block, the case cblink 1's
 * framework keys cannot carry.
 */

#include <errno.h>
#include <inttypes.h>

#include <cbor.h>

#include "cbl_test.h"

enum snode_kind { S_CONTAINER, S_LIST, S_STRING, S_UINT };

struct snode {
	uint64_t	 sid;
	uint64_t	 parent;	/* 0: top level */
	const char	*name;
	enum snode_kind	 kind;
};

static const struct snode schema[] = {
	{ 1490, 1501, "local-index",	S_UINT },
	{ 1500, 0,    "interfaces",	S_CONTAINER },
	{ 1501, 1500, "interface",	S_LIST },
	{ 1502, 1501, "name",		S_STRING },
	{ 1503, 1501, "description",	S_STRING },
	{ 1504, 1501, "mtu",		S_UINT },
};

static const struct snode *
snode(uint64_t sid)
{

	for (size_t i = 0; i < nitems(schema); i++)
		if (schema[i].sid == sid)
			return (&schema[i]);
	return (NULL);
}

/* A leaf as read back: its path by names and its value. */
struct leaf {
	char		path[128];
	uint64_t	sid;
	uint64_t	u;
	char		s[64];
};

struct rd {
	struct leaf	leaves[16];
	size_t		n;
	int		error;
	const char	*why;
};

static void
rd_fail(struct rd *r, const char *why)
{

	if (r->error == 0) {
		r->error = EPROTO;
		r->why = why;
	}
}

static void rd_node(struct rd *, const struct snode *, const char *,
    cbor_item_t *);

/* A map whose keys are deltas from "base" (0 at the top: absolute). */
static void
rd_map(struct rd *r, uint64_t base, const char *path, cbor_item_t *map)
{
	struct cbor_pair *p = cbor_map_handle(map);
	const struct snode *sn;
	int64_t delta;
	uint64_t sid;

	for (size_t i = 0; i < cbor_map_size(map); i++) {
		cbor_item_t *k = p[i].key;

		if (cbor_isa_uint(k))
			delta = (int64_t)cbor_get_int(k);
		else if (cbor_isa_negint(k) && base != 0)
			delta = -1 - (int64_t)cbor_get_int(k);
		else {
			rd_fail(r, "key is not a SID or a SID delta");
			return;
		}
		sid = (uint64_t)((int64_t)base + delta);
		if ((sn = snode(sid)) == NULL) {
			rd_fail(r, "unknown SID");
			return;
		}
		if (sn->parent != base) {
			rd_fail(r, "SID not a child of its parent");
			return;
		}
		rd_node(r, sn, path, p[i].value);
	}
}

static void
rd_node(struct rd *r, const struct snode *sn, const char *path,
    cbor_item_t *v)
{
	char sub[128];
	struct leaf *l;

	switch (sn->kind) {
	case S_CONTAINER:
		if (!cbor_isa_map(v)) {
			rd_fail(r, "container is not a map");
			return;
		}
		snprintf(sub, sizeof(sub), "%s/%s", path, sn->name);
		rd_map(r, sn->sid, sub, v);
		return;
	case S_LIST:
		if (!cbor_isa_array(v)) {
			rd_fail(r, "list is not an array");
			return;
		}
		for (size_t i = 0; i < cbor_array_size(v); i++) {
			cbor_item_t *e = cbor_array_handle(v)[i];

			if (!cbor_isa_map(e)) {
				rd_fail(r, "list entry is not a map");
				return;
			}
			snprintf(sub, sizeof(sub), "%s/%s[%zu]", path, sn->name,
			    i);
			rd_map(r, sn->sid, sub, e);
		}
		return;
	case S_STRING:
	case S_UINT:
		break;
	}
	if (r->n == nitems(r->leaves)) {
		rd_fail(r, "too many leaves");
		return;
	}
	l = &r->leaves[r->n++];
	memset(l, 0, sizeof(*l));
	snprintf(l->path, sizeof(l->path), "%s/%s", path, sn->name);
	l->sid = sn->sid;
	if (sn->kind == S_UINT) {
		if (!cbor_isa_uint(v)) {
			rd_fail(r, "uint leaf is not an unsigned integer");
			return;
		}
		l->u = cbor_get_int(v);
	} else {
		if (!cbor_isa_string(v) || !cbor_string_is_definite(v) ||
		    cbor_string_length(v) >= sizeof(l->s)) {
			rd_fail(r, "string leaf is not a short text string");
			return;
		}
		memcpy(l->s, cbor_string_handle(v), cbor_string_length(v));
	}
}

static int
rd_body(const unsigned char *p, size_t len, struct rd *r)
{
	struct cbor_load_result res;
	cbor_item_t *body;

	memset(r, 0, sizeof(*r));
	body = cbor_load(p, len, &res);
	if (body == NULL || res.error.code != CBOR_ERR_NONE || res.read != len)
		rd_fail(r, "not one CBOR item");
	else if (!cbor_isa_map(body))
		rd_fail(r, "body is not a map");
	else
		rd_map(r, 0, "", body);
	if (body != NULL)
		cbor_decref(&body);
	return (r->error);
}

/* Write a CBOR key or value; libcbor picks the shortest head. */
static size_t
put_int(unsigned char *p, size_t room, int64_t v)
{

	return (v >= 0 ? cbor_encode_uint((uint64_t)v, p, room) :
	    cbor_encode_negint((uint64_t)(-1 - v), p, room));
}

static size_t
put_text(unsigned char *p, size_t room, const char *s)
{
	size_t n, len = strlen(s);

	n = cbor_encode_string_start(len, p, room);
	ATF_REQUIRE(n != 0 && room - n >= len);
	memcpy(p + n, s, len);
	return (n + len);
}

#define	PUT(expr) do {						\
	size_t _n = (expr);					\
	ATF_REQUIRE(_n != 0);					\
	o += _n;						\
} while (0)

/*
 * One interface, by hand: { interfaces: { interface: [ { leaves } ] } }
 * with absolute SID 1500 at the top and deltas below it.
 */
static size_t
wr_one(unsigned char *buf, size_t room, const char *name, uint64_t mtu,
    bool local, uint64_t lindex)
{
	size_t o = 0;

	PUT(cbor_encode_map_start(1, buf + o, room - o));
	PUT(put_int(buf + o, room - o, 1500));		/* interfaces */
	PUT(cbor_encode_map_start(1, buf + o, room - o));
	PUT(put_int(buf + o, room - o, 1501 - 1500));	/* interface */
	PUT(cbor_encode_array_start(1, buf + o, room - o));
	PUT(cbor_encode_map_start(local ? 3 : 2, buf + o, room - o));
	if (local) {
		PUT(put_int(buf + o, room - o, 1490 - 1501));
		PUT(put_int(buf + o, room - o, (int64_t)lindex));
	}
	PUT(put_int(buf + o, room - o, 1502 - 1501));	/* name */
	PUT(put_text(buf + o, room - o, name));
	PUT(put_int(buf + o, room - o, 1504 - 1501));	/* mtu */
	PUT(put_int(buf + o, room - o, (int64_t)mtu));
	return (o);
}

static size_t
hexcmp(const unsigned char *p, size_t len, const char *hex)
{
	unsigned char want[256];
	size_t wlen;

	wlen = hex2bin(hex, want, sizeof(want));
	if (wlen != len || memcmp(p, want, len) != 0) {
		dump_hex("got", p, len);
		dump_hex("want", want, wlen);
		return (0);
	}
	return (len);
}

ATF_TC_WITHOUT_HEAD(round_trip);
ATF_TC_BODY(round_trip, tc)
{
	unsigned char buf[256], again[256];
	struct rd r;
	size_t len, len2;

	/* {1500: {1: [{1: "em0", 3: 1500}]}} */
	len = wr_one(buf, sizeof(buf), "em0", 1500, false, 0);
	ATF_REQUIRE(hexcmp(buf, len,
	    "A1 19 05DC A1 01 81 A2 01 63 656D30 03 19 05DC") == len);

	ATF_REQUIRE_EQ_MSG(0, rd_body(buf, len, &r), "%s", r.why);
	ATF_REQUIRE_EQ(2, r.n);
	ATF_CHECK_STREQ("/interfaces/interface[0]/name", r.leaves[0].path);
	ATF_CHECK_EQ(1502, r.leaves[0].sid);
	ATF_CHECK_STREQ("em0", r.leaves[0].s);
	ATF_CHECK_STREQ("/interfaces/interface[0]/mtu", r.leaves[1].path);
	ATF_CHECK_EQ(1504, r.leaves[1].sid);
	ATF_CHECK_EQ(1500, r.leaves[1].u);

	/* Written again from what was read: the same bytes. */
	len2 = wr_one(again, sizeof(again), r.leaves[0].s, r.leaves[1].u,
	    false, 0);
	ATF_REQUIRE_EQ(len, len2);
	ATF_REQUIRE(memcmp(buf, again, len) == 0);
}

ATF_TC_WITHOUT_HEAD(negative_delta);
ATF_TC_BODY(negative_delta, tc)
{
	unsigned char buf[256];
	struct rd r;
	size_t len;

	/* local-index at 1490 under interface at 1501: delta -11 (0x2A). */
	len = wr_one(buf, sizeof(buf), "em0", 1500, true, 7);
	ATF_REQUIRE(hexcmp(buf, len,
	    "A1 19 05DC A1 01 81 A3 2A 07 01 63 656D30 03 19 05DC") == len);
	ATF_REQUIRE_EQ_MSG(0, rd_body(buf, len, &r), "%s", r.why);
	ATF_REQUIRE_EQ(3, r.n);
	ATF_CHECK_STREQ("/interfaces/interface[0]/local-index",
	    r.leaves[0].path);
	ATF_CHECK_EQ(1490, r.leaves[0].sid);
	ATF_CHECK_EQ(7, r.leaves[0].u);
}

ATF_TC_WITHOUT_HEAD(refused);
ATF_TC_BODY(refused, tc)
{
	unsigned char buf[64];
	struct rd r;
	size_t len;

	/* A negative key at the top: SIDs are unsigned. */
	len = hex2bin("A1 2A 00", buf, sizeof(buf));
	ATF_CHECK_EQ(EPROTO, rd_body(buf, len, &r));
	/* A SID nobody defined. */
	len = hex2bin("A1 19 0600 00", buf, sizeof(buf));
	ATF_CHECK_EQ(EPROTO, rd_body(buf, len, &r));
	/* name (1502) given at the top, where only interfaces belongs. */
	len = hex2bin("A1 19 05DE 63 656D30", buf, sizeof(buf));
	ATF_CHECK_EQ(EPROTO, rd_body(buf, len, &r));
	/* A delta into another branch: interfaces + 2 is name, not ours. */
	len = hex2bin("A1 19 05DC A1 02 63 656D30", buf, sizeof(buf));
	ATF_CHECK_EQ(EPROTO, rd_body(buf, len, &r));
	/* mtu as text. */
	len = hex2bin("A1 19 05DC A1 01 81 A1 03 61 31", buf, sizeof(buf));
	ATF_CHECK_EQ(EPROTO, rd_body(buf, len, &r));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, round_trip);
	ATF_TP_ADD_TC(tp, negative_delta);
	ATF_TP_ADD_TC(tp, refused);
	return (atf_no_error());
}
