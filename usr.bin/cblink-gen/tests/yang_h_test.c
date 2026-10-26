/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The structs cblink-gen writes for YANG modules (yangh.h, made at build
 * time from shapes, edits, ietf-system and ietf-sid-file): that they
 * compile at WARNS=6 is most of the test; here, that they hold what a
 * reader would put in them, each shape once.  And their schema tables
 * (yangh_schema.c): children by SID, keys, choices, types shared, what
 * the runtime reads.
 */

#include <atf-c.h>
#include <errno.h>
#include <string.h>

#include <regex.h>

#include "yangh.h"
#include "yfill.h"

ATF_TC_WITHOUT_HEAD(shapes);
ATF_TC_BODY(shapes, tc)
{
	static const char *const names[] = { "a", "b" };
	static const enum shapes_shapes_levels levels[] = {
		SHAPES_SHAPES_LEVELS_VERY_HIGH,
	};
	static const struct shapes_shapes_eithers eithers[] = {
		{ .which = 0, .v.m0 = 7 }, { .which = 1, .v.m1 = "x" },
	};
	static const struct shapes_shapes_item items[] = {
		{ .id = 1 }, { .id = 2, .has_peer = true, .peer = 1 },
	};
	static const struct shapes_shapes_tuned tuned = {
		.has_max = true, .max = 9,
	};
	static const unsigned char perms[] = {
		1u << SHAPES_SHAPES_PERMS_READ,
	};
	struct shapes_shapes sh = {
		.default_ = "keyword",
		.has_ratio = true, .ratio = 150,
		.flag = true,
		.perms = { perms, sizeof(perms) },
		.has_level = true, .level = SHAPES_SHAPES_LEVEL_VERY_HIGH,
		.has_either = true,
		.either = { .which = 1, .v.m1 = SHAPES_SHAPES_EITHER_M1_LOW },
		.names = { 2, names },
		.levels = { 1, levels },
		.eithers = { 2, eithers },
		.tuned = &tuned,
		.how = SHAPES_SHAPES_HOW_CAREFUL,
		.check = SHAPES_SHAPES_CHECK_HASH, .hash = "sha256",
		.item = { 2, items },
	};
	struct shapes top = { .shapes = &sh };
	struct shapes_shapes_item_reset_input in = { .has_hard = true };
	struct shapes_note_body body = { .text = "hello" };
	struct shapes_note note = { .body = &body };

	ATF_CHECK_EQ(SHAPES_SHAPES_LEVEL_VERY_HIGH, 7);
	ATF_CHECK_EQ(SHAPES_SHAPES_PERMS_WRITE, 4u);
	ATF_CHECK_STREQ(top.shapes->default_, "keyword");
	ATF_CHECK_EQ(top.shapes->item.v[1].peer, 1u);
	ATF_CHECK_STREQ(top.shapes->eithers.v[1].v.m1, "x");
	ATF_CHECK_STREQ(top.shapes->names.v[1], "b");
	ATF_CHECK_EQ(top.shapes->tuned->max, 9);
	ATF_CHECK(top.shapes->check == SHAPES_SHAPES_CHECK_HASH);
	ATF_CHECK(in.has_hard && !in.hard);
	ATF_CHECK_STREQ(note.body->text, "hello");
	/* Nothing in an rpc's output: still a struct. */
	ATF_CHECK(sizeof(struct shapes_ping_output) > 0);
}

/* An IETF module and a structure: names with '-', a choice, a list. */
ATF_TC_WITHOUT_HEAD(ietf);
ATF_TC_BODY(ietf, tc)
{
	static const struct ietf_system_system_ntp_server servers[] = {
		{ .name = "a", .transport =
		    IETF_SYSTEM_SYSTEM_NTP_SERVER_TRANSPORT_UDP },
	};
	struct ietf_system_system_ntp ntp = {
		.has_enabled = true, .enabled = true, .server = { 1, servers },
	};
	struct ietf_system_system_clock clock = {
		.timezone = IETF_SYSTEM_SYSTEM_CLOCK_TIMEZONE_TIMEZONE_NAME,
		.timezone_name = "Asia/Tehran",
	};
	struct ietf_system_system sys = {
		.hostname = "edge1", .clock = &clock, .ntp = &ntp,
	};
	static const struct ietf_sid_file_sid_file_item item = {
		/* Keys: no has_ flag. */
		.namespace = IETF_SID_FILE_SID_FILE_ITEM_NAMESPACE_DATA,
		/* A union of two strings: which says the member. */
		.identifier = { .which = 1, .v.m1 = "/m:x" },
		.has_sid = true, .sid = 60000,
	};
	struct ietf_sid_file_sid_file sf = {
		.module_name = "m", .item = { 1, &item },
	};

	ATF_CHECK_STREQ(sys.ntp->server.v[0].name, "a");
	ATF_CHECK_STREQ(sys.clock->timezone_name, "Asia/Tehran");
	ATF_CHECK_EQ(sf.item.v[0].sid, 60000u);
	ATF_CHECK_STREQ(sf.item.v[0].identifier.v.m1, "/m:x");
	ATF_CHECK_EQ(IETF_SID_FILE_SID_FILE_ITEM_NAMESPACE_DATA, 3);
}

/* The tables, by a shorter name. */
static const struct cbl_yschema *const ys = &yangh_schema;

static const struct cbl_ymodule *
module(const char *name)
{

	for (uint32_t i = 0; i < yangh_schema.nmod; i++)
		if (strcmp(yangh_schema.mod[i]->name, name) == 0)
			return (yangh_schema.mod[i]);
	return (NULL);
}

static const struct cbl_ynode *
top(const struct cbl_ymodule *m, const char *name)
{

	for (uint32_t i = 0; m != NULL && i < m->ntop; i++)
		if (strcmp(m->top[i]->name, name) == 0)
			return (m->top[i]);
	return (NULL);
}

static const struct cbl_ynode *
child(const struct cbl_ynode *n, const char *name)
{

	for (uint32_t i = 0; n != NULL && i < n->nchild; i++)
		if (strcmp(n->child[i]->name, name) == 0)
			return (n->child[i]);
	return (NULL);
}

/* Children by SID, strictly; keys that are key leaves.  Its count. */
static size_t
check_tree(const struct cbl_ynode *n)
{
	size_t k = 1;

	ATF_CHECK_MSG(n->sid != 0, "%s: no SID", n->name);
	for (uint32_t i = 0; i < n->nchild; i++) {
		if (i > 0)
			ATF_CHECK_MSG(n->child[i]->sid > n->child[i - 1]->sid,
			    "%s: %s before %s", n->name, n->child[i - 1]->name,
			    n->child[i]->name);
		k += check_tree(n->child[i]);
	}
	for (uint16_t i = 0; i < n->nkeys; i++)
		ATF_CHECK(n->keys[i] < n->nchild &&
		    (n->child[n->keys[i]]->flags & CBL_YNF_KEY) != 0);
	return (k);
}

ATF_TC_WITHOUT_HEAD(tables);
ATF_TC_BODY(tables, tc)
{
	const struct cbl_ymodule *sh, *sys;
	const struct cbl_ynode *n, *s, *item, *x;
	const struct cbl_ytype *t;
	size_t nodes = 0;
	regex_t re;

	ATF_REQUIRE_EQ(11u, yangh_schema.nmod);
	ATF_REQUIRE((sh = module("shapes")) != NULL);
	ATF_REQUIRE((sys = module("ietf-system")) != NULL);
	ATF_REQUIRE(module("ietf-sid-file") != NULL);
	ATF_REQUIRE(module("edits") != NULL);
	ATF_REQUIRE(module("wdexample") != NULL);
	for (uint32_t i = 0; i < yangh_schema.nmod; i++)
		for (uint32_t j = 0; j < yangh_schema.mod[i]->ntop; j++) {
			if (j > 0)
				ATF_CHECK(yangh_schema.mod[i]->top[j]->sid >
				    yangh_schema.mod[i]->top[j - 1]->sid);
			nodes += check_tree(yangh_schema.mod[i]->top[j]);
		}
	ATF_CHECK(nodes > 100);

	/* shapes: SIDs from its .sid file, by -a. */
	ATF_CHECK_EQ(UINT64_C(1099511727776), sh->sid);
	ATF_REQUIRE((s = top(sh, "shapes")) != NULL);
	ATF_CHECK_EQ(CBL_YN_CONTAINER, s->kind);
	ATF_CHECK(s->flags & CBL_YNF_CONFIG);
	n = child(s, "ratio");
	ATF_REQUIRE(n != NULL && n->type != NULL);
	ATF_CHECK_EQ(CBL_YT_DECIMAL64, n->type->kind);
	ATF_CHECK_EQ(2, n->type->fdigits);
	n = child(s, "colour");
	ATF_REQUIRE(n != NULL && n->type->kind == CBL_YT_IDENTITYREF);
	ATF_REQUIRE_EQ(1, n->type->nbases);
	ATF_CHECK_EQ(UINT64_C(1099511727777), n->type->bases[0]);
	/* A union, an enumeration among its members, shared with level. */
	n = child(s, "either");
	ATF_REQUIRE(n != NULL && n->type->kind == CBL_YT_UNION);
	ATF_REQUIRE_EQ(3, n->type->nmembers);
	t = n->type->members[1];
	ATF_CHECK_EQ(CBL_YT_ENUMERATION, t->kind);
	ATF_REQUIRE_EQ(2u, t->nitems);
	ATF_CHECK_STREQ("very high", t->items[1].name);
	ATF_CHECK_EQ(7, t->items[1].value);
	ATF_CHECK(child(s, "level")->type == t);
	/* Choices: a case's node says which; a choice in a case, its own. */
	n = child(s, "speed");
	ATF_REQUIRE(n != NULL && n->choice != NULL);
	ATF_CHECK_STREQ("how", n->choice->name);
	ATF_CHECK_STREQ("fast", n->choice->cases[n->ccase].name);
	n = child(s, "crc");
	ATF_REQUIRE(n != NULL && n->choice != NULL);
	ATF_CHECK_STREQ("check", n->choice->name);
	ATF_REQUIRE(n->choice->parent != NULL);
	ATF_CHECK_STREQ("how", n->choice->parent->name);
	ATF_CHECK_STREQ("careful",
	    n->choice->parent->cases[n->choice->parent_case].name);
	/* A list, its key, an action and a notification in it, a leafref. */
	item = child(s, "item");
	ATF_REQUIRE(item != NULL && item->kind == CBL_YN_LIST);
	ATF_REQUIRE_EQ(1, item->nkeys);
	ATF_CHECK_STREQ("id", item->child[item->keys[0]]->name);
	ATF_CHECK(child(item, "reset") != NULL &&
	    child(item, "reset")->kind == CBL_YN_ACTION);
	ATF_CHECK(child(child(item, "reset"), "input") != NULL);
	ATF_CHECK(child(item, "changed") != NULL &&
	    child(item, "changed")->kind == CBL_YN_NOTIF);
	n = child(item, "peer");
	ATF_REQUIRE(n != NULL);
	ATF_CHECK_EQ(CBL_YT_UINT32, n->type->kind);
	ATF_CHECK(n->type->flags & CBL_YTF_LEAFREF);
	ATF_REQUIRE(n->type->path >= 0 &&
	    (uint32_t)n->type->path < yangh_schema.nxpath);
	/* As the evaluator reads it: each step's axis, each name's module. */
	ATF_CHECK_STREQ("parent::node()/child::shapes:id",
	    yangh_schema.xpath[n->type->path]);
	n = child(child(s, "tuned"), "max");
	ATF_CHECK(n != NULL && (n->flags & CBL_YNF_MANDATORY));
	ATF_CHECK(child(s, "tuned")->flags & CBL_YNF_PRESENCE);
	x = top(sh, "note");
	ATF_REQUIRE(x != NULL);
	ATF_CHECK_EQ(CBL_YN_STRUCTURE, x->kind);
	ATF_CHECK(child(x, "body") != NULL);
	ATF_CHECK(top(sh, "ping") != NULL && top(sh, "ping")->kind ==
	    CBL_YN_RPC);

	/* ietf-system: IANA's SIDs, a pattern as an ERE, a must. */
	n = child(top(sys, "system"), "hostname");
	ATF_REQUIRE(n != NULL);
	ATF_CHECK_EQ(UINT64_C(1752), n->sid);
	ATF_REQUIRE(n->type->npatterns > 0);
	ATF_REQUIRE(regcomp(&re, n->type->patterns[0].ere, REG_EXTENDED |
	    REG_NOSUB) == 0);
	ATF_CHECK(regexec(&re, "edge1.example.com", 0, NULL, 0) == 0);
	ATF_CHECK(regexec(&re, "-bad-", 0, NULL, 0) != 0);
	regfree(&re);
	n = child(top(sys, "system"), "authentication");
	ATF_REQUIRE(n != NULL);
	n = child(n, "user-authentication-order");
	ATF_REQUIRE(n != NULL && n->nmust == 1);
	ATF_CHECK(strstr(yangh_schema.xpath[n->must[0].expr], "radius") !=
	    NULL);
	ATF_CHECK(n->kind == CBL_YN_LEAFLIST && (n->flags &
	    CBL_YNF_USERORDER));
}

/* Every identityref base under n: in the table, its closure too. */
static size_t
check_bases(const struct cbl_ytype *t)
{
	const struct cbl_yident *b;
	size_t k = 0;

	if (t == NULL)
		return (0);
	for (uint16_t i = 0; i < t->nmembers; i++)
		k += check_bases(t->members[i]);
	for (uint16_t i = 0; i < t->nbases; i++) {
		b = cbl_yschema_ident(ys, t->bases[i]);
		ATF_CHECK_MSG(b != NULL, "base %ju not in the table",
		    (uintmax_t)t->bases[i]);
		if (b == NULL)
			continue;
		for (uint32_t j = 0; j < b->nderived; j++) {
			ATF_CHECK_MSG(cbl_yschema_ident(ys, b->derived[j]) !=
			    NULL, "%s: derived %ju not in the table", b->name,
			    (uintmax_t)b->derived[j]);
			if (j > 0)
				ATF_CHECK(b->derived[j] > b->derived[j - 1]);
			ATF_CHECK(cbl_yderived_from(ys, b->derived[j], b->sid,
			    false));
			ATF_CHECK(!cbl_yderived_from(ys, b->sid, b->derived[j],
			    false));
		}
		ATF_CHECK(!cbl_yderived_from(ys, b->sid, b->sid, false));
		ATF_CHECK(cbl_yderived_from(ys, b->sid, b->sid, true));
		k++;
	}
	return (k);
}

static size_t
check_idrefs(const struct cbl_ynode *n)
{
	size_t k = check_bases(n->type);

	for (uint32_t i = 0; i < n->nchild; i++)
		k += check_idrefs(n->child[i]);
	return (k);
}

/*
 * Every child found by its delta, every node by its SID, and a SID in a
 * table's span that is no child's, not.  How many of each way.
 */
static void
check_lookup(const struct cbl_ynode *n, size_t *dense, size_t *mapped)
{
	ATF_CHECK(cbl_yschema_node(ys, n->sid) == n);
	/* An input's and an output's deltas are from the rpc's SID. */
	ATF_CHECK((n->kind == CBL_YN_INPUT || n->kind == CBL_YN_OUTPUT) ==
	    (n->base != 0 && n->base != n->sid));
	if (n->nmap > 0 && n->map == NULL)
		(*dense)++;
	else if (n->nmap > 0)
		(*mapped)++;
	for (uint32_t i = 0; i < n->nchild; i++) {
		ATF_CHECK_MSG(cbl_ynode_child(n, (int64_t)(n->child[i]->sid -
		    cbl_ynode_base(n))) == n->child[i], "%s/%s", n->name,
		    n->child[i]->name);
		check_lookup(n->child[i], dense, mapped);
	}
	for (uint32_t off = 0; n->map != NULL && off < n->nmap; off++)
		if (n->map[off] == 0)
			ATF_CHECK(cbl_ynode_child(n, (int64_t)
			    (n->child[0]->sid + off - cbl_ynode_base(n))) == NULL);
	ATF_CHECK(cbl_ynode_child(n, INT64_MIN) == NULL);
}

ATF_TC_WITHOUT_HEAD(lookups);
ATF_TC_BODY(lookups, tc)
{
	const struct cbl_ynode *n;
	size_t dense = 0, mapped = 0;

	ATF_REQUIRE(yangh_schema.nnode > 100);
	for (uint32_t i = 1; i < yangh_schema.nnode; i++)
		ATF_CHECK(yangh_schema.node[i]->sid >
		    yangh_schema.node[i - 1]->sid);
	for (uint32_t i = 0; i < yangh_schema.nmod; i++)
		for (uint32_t j = 0; j < yangh_schema.mod[i]->ntop; j++)
			check_lookup(yangh_schema.mod[i]->top[j], &dense,
			    &mapped);
	ATF_CHECK(dense > 0);
	ATF_CHECK(mapped > 0);
	/* Two leaves, numbered one after the other: dense. */
	n = child(top(module("ietf-sid-file"), "sid-file"),
	    "assignment-range");
	ATF_REQUIRE(n != NULL);
	ATF_CHECK_EQ(2u, n->nmap);
	ATF_CHECK(n->map == NULL);
	ATF_CHECK_STREQ("size", cbl_ynode_child(n, 2)->name);
	/* Their children between them: by a table. */
	n = top(module("shapes"), "shapes");
	ATF_REQUIRE(n != NULL && n->map != NULL);
	ATF_CHECK_STREQ("item", cbl_ynode_child(n, (int64_t)(child(n,
	    "item")->sid - n->sid))->name);
	ATF_CHECK(cbl_yschema_node(ys, 1) == NULL);
}

/*
 * Every struct of the tables, filled by them, through YANG-CBOR and
 * back: three passes, every optional and only what must be.  And one
 * filled by hand, its bytes as RFC 9254 has them.
 */
ATF_TC_WITHOUT_HEAD(roundtrip);
ATF_TC_BODY(roundtrip, tc)
{
	/* RFC 9254's encoding, by the SIDs of RFC 9595's ietf-system. */
	static const uint8_t want[] = {
		0xa2,			/* system (1717) {		*/
		0x15, 0xa1,		/*  +21 clock (1738) {		*/
		0x02, 0x38, 0xd1,	/*   +2 timezone-utc-offset: -210 */
		0x18, 0x23,		/*  }, +35 hostname (1752):	*/
		0x65, 'e', 'd', 'g', 'e', '1',	/* "edge1" }		*/
	};
	struct ietf_system_system_clock clock = {
		.timezone = IETF_SYSTEM_SYSTEM_CLOCK_TIMEZONE_TIMEZONE_UTC_OFFSET,
		.has_timezone_utc_offset = true, .timezone_utc_offset = -210,
	};
	struct ietf_system_system sys = { .hostname = "edge1",
	    .clock = &clock };
	struct ietf_system_system back;
	struct cbl_ybuf b = { 0 };
	cbl_yarena *a;
	char why[256];
	size_t n = 0;

	ATF_CHECK_EQ_MSG(0u, yround_all(ys, &n, why, sizeof(why)), "%s", why);
	ATF_CHECK(n > 100);

	/* system {clock {timezone-utc-offset -210}, hostname "edge1"}. */
	ATF_REQUIRE_EQ(0, ietf_system_system_encode(&sys, &b));
	ATF_CHECK_EQ(sizeof(want), b.len);
	ATF_CHECK(b.len == sizeof(want) && memcmp(want, b.p, b.len) == 0);
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	ATF_REQUIRE_EQ_MSG(0, ietf_system_system_decode(b.p, b.len, &back,
	    a, CBL_YD_STRICT, why, sizeof(why)), "%s", why);
	ATF_CHECK_STREQ("edge1", back.hostname);
	ATF_REQUIRE(back.clock != NULL);
	ATF_CHECK(back.clock->timezone ==
	    IETF_SYSTEM_SYSTEM_CLOCK_TIMEZONE_TIMEZONE_UTC_OFFSET);
	ATF_CHECK(back.clock->has_timezone_utc_offset);
	ATF_CHECK_EQ(-210, back.clock->timezone_utc_offset);
	ATF_CHECK(back.ntp == NULL && back.contact == NULL);
	/* hostname "\xff": not UTF-8, refused. */
	{
		static const uint8_t bad[] = { 0xa1, 0x18, 0x23, 0x61, 0xff };

		ATF_CHECK_EQ(EINVAL, ietf_system_system_decode(bad,
		    sizeof(bad), &back, a, 0, why, sizeof(why)));
		ATF_CHECK(strstr(why, "UTF-8") != NULL);
	}
	/* A key it has no child for: refused strictly, skipped else. */
	{
		static const uint8_t extra[] = { 0xa1, 0x18, 0x63, 0xf6 };

		ATF_CHECK(ietf_system_system_decode(extra, sizeof(extra),
		    &back, a, CBL_YD_STRICT, why, sizeof(why)) != 0);
		ATF_CHECK_EQ(0, ietf_system_system_decode(extra,
		    sizeof(extra), &back, a, 0, why, sizeof(why)));
	}
	cbl_yarena_free(a);
	cbl_ybuf_free(&b);
}

/*
 * A thousand empty list entries are a thousand bytes, and a thousand
 * structs: what a decode allocates is the arena's limit's to bound.
 */
ATF_TC_WITHOUT_HEAD(arena_limit);
ATF_TC_BODY(arena_limit, tc)
{
	const struct cbl_ynode *s, *item;
	struct shapes_shapes out;
	uint8_t in[1024], *p = in;
	uint64_t delta;
	cbl_yarena *a;
	char why[256];

	ATF_REQUIRE((s = top(module("shapes"), "shapes")) != NULL);
	ATF_REQUIRE((item = child(s, "item")) != NULL);
	delta = item->sid - s->sid;
	ATF_REQUIRE(delta < 24);
	*p++ = 0xa1;			/* { delta: [ {} x 1000 ] } */
	*p++ = (uint8_t)delta;
	*p++ = 0x99;			/* an array, a 16-bit count */
	*p++ = 1000 >> 8;
	*p++ = 1000 & 0xff;
	for (int i = 0; i < 1000 && p < in + sizeof(in); i++)
		*p++ = 0xa0;
	ATF_REQUIRE(p - in == 1005);

	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	cbl_yarena_set_limit(a, 4096);
	ATF_CHECK_EQ(ENOMEM, shapes_shapes_decode(in, (size_t)(p - in), &out,
	    a, 0, why, sizeof(why)));
	ATF_CHECK(strstr(why, "limit") != NULL);
	cbl_yarena_free(a);
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	ATF_CHECK_EQ(0, shapes_shapes_decode(in, (size_t)(p - in), &out, a, 0,
	    why, sizeof(why)));
	ATF_CHECK_EQ(1000u, out.item.n);
	cbl_yarena_free(a);
}

/*
 * One kind at a time (PLAN-SDN-YANG 1.7.3), as RFC 9254 section 6 has it:
 * the bytes of {the leaf's delta: its value} written, and those the RFC
 * allows besides read.
 */

/* A map's key: a delta, as CBOR (all of shapes' are below 256). */
static size_t
key_bytes(uint8_t *p, uint64_t delta)
{

	if (delta < 24) {
		p[0] = (uint8_t)delta;
		return (1);
	}
	p[0] = 0x18;
	p[1] = (uint8_t)delta;
	return (2);
}

/* shapes with this leaf alone: its encoding, {delta: value}. */
static void
check_leaf(const struct shapes_shapes *sh, const char *leaf,
    const uint8_t *value, size_t vlen)
{
	const struct cbl_ynode *s = top(module("shapes"), "shapes");
	struct cbl_ybuf b = { 0 };
	uint8_t want[64];
	size_t n;

	want[0] = 0xa1;
	n = 1 + key_bytes(want + 1, child(s, leaf)->sid - s->sid);
	memcpy(want + n, value, vlen);
	n += vlen;
	ATF_REQUIRE_EQ(0, shapes_shapes_encode(sh, &b));
	ATF_CHECK_EQ_MSG(n, b.len, "%s: %zu bytes, %zu wanted", leaf, b.len,
	    n);
	ATF_CHECK_MSG(b.len == n && memcmp(b.p, want, n) == 0, "%s: not the "
	    "bytes wanted", leaf);
	cbl_ybuf_free(&b);
}

/* {leaf's delta: value} read into out; 0 or the error. */
static int
read_leaf(const char *leaf, const uint8_t *value, size_t vlen,
    struct shapes_shapes *out, cbl_yarena *a)
{
	const struct cbl_ynode *s = top(module("shapes"), "shapes");
	uint8_t in[64];
	char why[256];
	size_t n;

	in[0] = 0xa1;
	n = 1 + key_bytes(in + 1, child(s, leaf)->sid - s->sid);
	memcpy(in + n, value, vlen);
	return (shapes_shapes_decode(in, n + vlen, out, a, CBL_YD_STRICT, why,
	    sizeof(why)));
}

/*
 * An rpc's input: its children's deltas are from the rpc's SID, not the
 * input's (RFC 9254 section 3.2): /shapes:ping is 2^40 + 100008, its
 * input/count 2^40 + 100010, so count 5 is {2: 5}.
 */
ATF_TC_WITHOUT_HEAD(rpc_deltas);
ATF_TC_BODY(rpc_deltas, tc)
{
	struct shapes_ping_input in = { .has_count = true, .count = 5 }, got;
	struct cbl_ybuf b = { 0 };
	cbl_yarena *a;

	ATF_REQUIRE_EQ(0, shapes_ping_input_encode(&in, &b));
	ATF_REQUIRE_EQ(3, b.len);
	ATF_CHECK(memcmp(b.p, "\xa1\x02\x05", 3) == 0);
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	memset(&got, 0, sizeof(got));
	ATF_REQUIRE_EQ(0, shapes_ping_input_decode(b.p, b.len, &got, a,
	    CBL_YD_STRICT, NULL, 0));
	ATF_CHECK(got.has_count && got.count == 5);
	/* The input's own SID as the base: delta 1, no such child. */
	memset(&got, 0, sizeof(got));
	ATF_CHECK(shapes_ping_input_decode("\xa1\x01\x05", 3, &got, a,
	    CBL_YD_STRICT, NULL, 0) != 0 || !got.has_count);
	/* cbl_ydecode() zeroes the struct: nothing of before stays (as
	 * fuzz_ycodec found, decoding into one buffer again and again). */
	memset(&got, 0xa5, sizeof(got));
	ATF_REQUIRE_EQ(0, cbl_ydecode(cbl_yschema_node(&yangh_schema,
	    UINT64_C(1099511727785)), "\xa0", 1, &got, a, CBL_YD_STRICT, NULL,
	    0));
	ATF_CHECK(!got.has_count);
	cbl_yarena_free(a);
	cbl_ybuf_free(&b);
}

ATF_TC_WITHOUT_HEAD(kinds);
ATF_TC_BODY(kinds, tc)
{
	static uint8_t perms[] = { 0x11, 0x00 };
	struct shapes_shapes sh, got;
	uint64_t red;
	cbl_yarena *a;

	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	red = UINT64_C(1099511727778);

	/* decimal64: 2.57 of two fraction digits is 4([-2, 257]). */
	memset(&sh, 0, sizeof(sh));
	sh.has_ratio = true;
	sh.ratio = 257;
	check_leaf(&sh, "ratio", (const uint8_t *)"\xc4\x82\x21\x19\x01\x01",
	    6);
	ATF_CHECK_EQ(EINVAL, read_leaf("ratio", (const uint8_t *)
	    "\xc4\x82\x22\x19\x01\x01", 6, &got, a));	/* three digits */

	/* empty: null. */
	memset(&sh, 0, sizeof(sh));
	sh.flag = true;
	check_leaf(&sh, "flag", (const uint8_t *)"\xf6", 1);

	/* bits: bytes, a trailing zero byte never sent. */
	memset(&sh, 0, sizeof(sh));
	sh.perms.p = perms;
	sh.perms.len = sizeof(perms);
	check_leaf(&sh, "perms", (const uint8_t *)"\x41\x11", 2);
	/* The sparse form: h'01', two zero bytes, h'02': 0 and 17. */
	ATF_REQUIRE_EQ(0, read_leaf("wide", (const uint8_t *)
	    "\x83\x41\x01\x01\x41\x02", 6, &got, a));
	ATF_REQUIRE_EQ(3u, got.wide.len);
	ATF_CHECK(memcmp(got.wide.p, "\x01\x00\x02", 3) == 0);
	ATF_CHECK_EQ(EINVAL, read_leaf("wide", (const uint8_t *)
	    "\x81\x41\x01", 3, &got, a));	/* one byte string: bare */
	ATF_CHECK_EQ(EINVAL, read_leaf("wide", (const uint8_t *)
	    "\x82\x41\x00\x01", 4, &got, a));	/* ends in a zero byte */
	ATF_CHECK_EQ(EINVAL, read_leaf("wide", (const uint8_t *)
	    "\x82\x41\x01\x41\x02", 5, &got, a));	/* two strings at once */
	ATF_CHECK_EQ(EINVAL, read_leaf("wide", (const uint8_t *)
	    "\x83\x41\x01\x1a\x7f\xff\xff\xff\x41\x02", 10, &got, a));

	/* identityref: its SID; read by name too, qualified or not. */
	memset(&sh, 0, sizeof(sh));
	sh.has_colour = true;
	sh.colour = red;
	check_leaf(&sh, "colour", (const uint8_t *)
	    "\x1b\x00\x00\x01\x00\x00\x01\x86\xa2", 9);
	ATF_REQUIRE_EQ(0, read_leaf("colour", (const uint8_t *)"\x63red", 4,
	    &got, a));
	ATF_CHECK_EQ(red, got.colour);
	ATF_REQUIRE_EQ(0, read_leaf("colour", (const uint8_t *)
	    "\x6ashapes:red", 11, &got, a));
	ATF_CHECK_EQ(red, got.colour);
	ATF_CHECK_EQ(EINVAL, read_leaf("colour", (const uint8_t *)
	    "\x65x:red", 6, &got, a));

	/* instance-identifier: the CBOR it is, a SID with a key here. */
	memset(&sh, 0, sizeof(sh));
	sh.target.p = "\x82\x19\x06\xa4\x61k";
	sh.target.len = 6;
	check_leaf(&sh, "target", (const uint8_t *)"\x82\x19\x06\xa4\x61k", 6);

	/* union: as its member, an enumeration tagged 44 by name. */
	memset(&sh, 0, sizeof(sh));
	sh.has_either = true;
	sh.either.which = 0;
	sh.either.v.m0 = -5;
	check_leaf(&sh, "either", (const uint8_t *)"\x24", 1);
	sh.either.which = 1;
	sh.either.v.m1 = SHAPES_SHAPES_EITHER_M1_LOW;
	check_leaf(&sh, "either", (const uint8_t *)"\xd8\x2c\x63low", 6);
	sh.either.which = 2;
	sh.either.v.m2 = "x";
	check_leaf(&sh, "either", (const uint8_t *)"\x61x", 2);
	/* And 46, 43 by name, 45. */
	memset(&sh, 0, sizeof(sh));
	sh.has_pointer = true;
	sh.pointer.which = 1;
	sh.pointer.v.m1.p = "\x01\x02";		/* a and b */
	sh.pointer.v.m1.len = 2;
	check_leaf(&sh, "pointer", (const uint8_t *)"\xd8\x2b\x63\x61\x20\x62",
	    6);
	ATF_REQUIRE_EQ(0, read_leaf("pointer", (const uint8_t *)
	    "\xd8\x2b\x63\x61\x20\x62", 6, &got, a));
	ATF_CHECK_EQ(1u, got.pointer.which);
	ATF_CHECK(got.pointer.v.m1.len == 2 &&
	    memcmp(got.pointer.v.m1.p, "\x01\x02", 2) == 0);
	ATF_REQUIRE_EQ(0, read_leaf("pointer", (const uint8_t *)
	    "\xd8\x2e\x19\x06\xa4", 5, &got, a));
	ATF_CHECK_EQ(0u, got.pointer.which);
	ATF_REQUIRE_EQ(0, read_leaf("pointer", (const uint8_t *)
	    "\xd8\x2d\x63red", 6, &got, a));
	ATF_CHECK_EQ(2u, got.pointer.which);
	ATF_CHECK_EQ(red, got.pointer.v.m2);
	ATF_CHECK_EQ(EINVAL, read_leaf("pointer", (const uint8_t *)
	    "\xd8\x2b\x61\x63", 4, &got, a));	/* no bit c */
	cbl_yarena_free(a);
}

/* json's text has want in it. */
static void
check_json(const struct cbl_ybuf *b, const char *want)
{

	ATF_CHECK_MSG(memmem(b->p, b->len, want, strlen(want)) != NULL,
	    "%s not in %.*s", want, (int)b->len, (const char *)b->p);
}

/*
 * RFC 7951's JSON of a value (cbl_yjson()): names qualified at the top,
 * decimal64 and 64-bit integers as strings, empty [null], bits and
 * enumerations by name, an identity with its module, binary base64,
 * strings escaped, a union as its member, leaf-lists as arrays.
 */
ATF_TC_WITHOUT_HEAD(json);
ATF_TC_BODY(json, tc)
{
	static uint8_t perms[] = { 0x11 };
	static const char *const names[] = { "x", "y" };
	struct shapes_shapes sh;
	struct shapes data = { &sh };
	struct cbl_ybuf b = { NULL, 0, 0 };
	const struct cbl_ymodule *m;

	ATF_REQUIRE((m = module("shapes")) != NULL);
	memset(&sh, 0, sizeof(sh));
	sh.default_ = "a \"q\"\n";
	sh.has_ratio = true;
	sh.ratio = -5;
	sh.flag = true;
	sh.blob.p = "abc";
	sh.blob.len = 3;
	sh.perms.p = perms;
	sh.perms.len = sizeof(perms);
	sh.has_level = true;
	sh.level = SHAPES_SHAPES_LEVEL_VERY_HIGH;
	sh.has_colour = true;
	sh.colour = UINT64_C(1099511727778);
	sh.has_either = true;
	sh.either.which = 0;
	sh.either.v.m0 = -5;
	sh.names.n = 2;
	sh.names.v = names;
	ATF_REQUIRE_EQ(0, cbl_yjson_module(m, &data, &b));
	ATF_CHECK(b.len > 2 && memcmp(b.p, "{\"shapes:shapes\":{", 18) == 0 &&
	    ((const char *)b.p)[b.len - 1] == '}');
	check_json(&b, "\"default\":\"a \\\"q\\\"\\u000a\"");
	check_json(&b, "\"ratio\":\"-0.05\"");
	check_json(&b, "\"flag\":[null]");
	check_json(&b, "\"blob\":\"YWJj\"");
	check_json(&b, "\"perms\":\"read write\"");
	check_json(&b, "\"level\":\"very high\"");
	check_json(&b, "\"colour\":\"shapes:red\"");
	check_json(&b, "\"either\":-5");
	check_json(&b, "\"names\":[\"x\",\"y\"]");
	/* Absent members are left out. */
	ATF_CHECK(memmem(b.p, b.len, "\"wide\"", 6) == NULL &&
	    memmem(b.p, b.len, "\"tuned\"", 7) == NULL);
	cbl_ybuf_free(&b);
	/* A node's children, unqualified below the top. */
	ATF_REQUIRE_EQ(0, cbl_yjson(top(m, "shapes"), &sh, &b));
	ATF_CHECK(b.len > 0 && ((const char *)b.p)[0] == '{' &&
	    memmem(b.p, b.len, "\"shapes:shapes\"", 15) == NULL &&
	    memmem(b.p, b.len, "\"default\":", 10) != NULL);
	cbl_ybuf_free(&b);
}

/*
 * A version 2 message: {SID of shapes: its value}, through a frame and
 * back, its decimal64 tagged 4 and its union's enumeration 44, which the
 * body decoder takes as it is.
 */
ATF_TC_WITHOUT_HEAD(message);
ATF_TC_BODY(message, tc)
{
	struct shapes_shapes sh = {
		.has_ratio = true, .ratio = 3165,
		.has_either = true,
		.either = { .which = 1, .v.m1 = SHAPES_SHAPES_EITHER_M1_VERY_HIGH },
		.how = SHAPES_SHAPES_HOW_FAST, .has_speed = true, .speed = 9,
	}, back;
	const struct cbl_ynode *n;
	const void *frame;
	size_t len, used;
	cbl_ctx *ctx;
	cbl_msg *msg, *got;
	cbl_yarena *a;
	char why[256];

	ATF_REQUIRE((n = top(module("shapes"), "shapes")) != NULL);
	ATF_REQUIRE_EQ(0, cbl_ctx_new(&ctx));
	ATF_REQUIRE_EQ(0, cbl_msg_new(ctx, 1, 1, CBL_F_REQUEST, &msg));
	ATF_REQUIRE_EQ(0, cbl_msg_put_ynode(msg, n, &sh));
	ATF_REQUIRE_EQ(0, cbl_msg_encode(msg, &frame, &len));
	ATF_REQUIRE_EQ(0, cbl_frame_decode(ctx, frame, len, &used, &got));
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	ATF_REQUIRE_EQ_MSG(0, cbl_msg_ydecode(got, n, &back, a, CBL_YD_STRICT,
	    why, sizeof(why)), "%s", why);
	ATF_CHECK(back.has_ratio && back.ratio == 3165);
	ATF_CHECK(back.has_either && back.either.which == 1 &&
	    back.either.v.m1 == SHAPES_SHAPES_EITHER_M1_VERY_HIGH);
	ATF_CHECK(back.how == SHAPES_SHAPES_HOW_FAST && back.speed == 9);
	/* Another node's SID: not in this body. */
	ATF_CHECK_EQ(ENOENT, cbl_msg_ydecode(got, top(module("shapes"),
	    "note"), &back, a, 0, why, sizeof(why)));
	cbl_yarena_free(a);
	cbl_msg_free(got);
	cbl_msg_free(msg);
	cbl_ctx_free(ctx);
}

ATF_TC_WITHOUT_HEAD(identities);
ATF_TC_BODY(identities, tc)
{
	const struct cbl_ymodule *sys;
	const struct cbl_yident *colour, *red, *m;
	size_t bases = 0;

	ATF_REQUIRE(yangh_schema.nident > 0);
	for (uint32_t i = 1; i < yangh_schema.nident; i++)
		ATF_CHECK(yangh_schema.ident[i].sid >
		    yangh_schema.ident[i - 1].sid);
	for (uint32_t i = 0; i < yangh_schema.nmod; i++)
		for (uint32_t j = 0; j < yangh_schema.mod[i]->ntop; j++)
			bases += check_idrefs(yangh_schema.mod[i]->top[j]);
	ATF_CHECK(bases >= 3);

	/* shapes: red is a colour, colour is not red. */
	ATF_REQUIRE((colour = cbl_yschema_ident(&yangh_schema,
	    UINT64_C(1099511727777))) != NULL);
	ATF_CHECK_STREQ("colour", colour->name);
	ATF_CHECK_STREQ("shapes", colour->module->name);
	ATF_REQUIRE((red = cbl_yschema_ident(&yangh_schema,
	    UINT64_C(1099511727778))) != NULL);
	ATF_CHECK_STREQ("red", red->name);
	ATF_CHECK(cbl_yderived_from(ys, red->sid, colour->sid, false));
	ATF_CHECK(!cbl_yderived_from(ys, colour->sid, red->sid, true));
	ATF_CHECK_EQ(0u, red->nderived);

	/* ietf-system: RADIUS and local users are ways to authenticate. */
	m = NULL;
	for (uint32_t i = 0; i < yangh_schema.nident; i++)
		if (strcmp(yangh_schema.ident[i].name,
		    "authentication-method") == 0)
			m = &yangh_schema.ident[i];
	ATF_REQUIRE(m != NULL);
	ATF_CHECK_EQ(2u, m->nderived);
	for (uint32_t i = 0; i < yangh_schema.nident; i++)
		if (strcmp(yangh_schema.ident[i].name, "radius") == 0 ||
		    strcmp(yangh_schema.ident[i].name, "local-users") == 0)
			ATF_CHECK(cbl_yderived_from(ys,
			    yangh_schema.ident[i].sid, m->sid, false));

	/* Features, as the schema was compiled: every one on. */
	ATF_REQUIRE((sys = module("ietf-system")) != NULL);
	ATF_REQUIRE(sys->nfeature > 0);
	for (uint32_t i = 0; i < sys->nfeature; i++) {
		ATF_CHECK(sys->feature[i].sid != 0);
		ATF_CHECK(sys->feature[i].enabled);
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, shapes);
	ATF_TP_ADD_TC(tp, ietf);
	ATF_TP_ADD_TC(tp, tables);
	ATF_TP_ADD_TC(tp, identities);
	ATF_TP_ADD_TC(tp, lookups);
	ATF_TP_ADD_TC(tp, roundtrip);
	ATF_TP_ADD_TC(tp, arena_limit);
	ATF_TP_ADD_TC(tp, kinds);
	ATF_TP_ADD_TC(tp, json);
	ATF_TP_ADD_TC(tp, rpc_deltas);
	ATF_TP_ADD_TC(tp, message);
	return (atf_no_error());
}
