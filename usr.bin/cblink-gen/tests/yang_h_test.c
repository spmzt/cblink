/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The structs cblink-gen writes for YANG modules (yangh.h, made at build
 * time from shapes, ietf-system and ietf-sid-file): that they compile at
 * WARNS=6 is most of the test; here, that they hold what a reader would
 * put in them, each shape once.  And their schema tables (yangh_schema.c):
 * children by SID, keys, choices, types shared, what the runtime reads.
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

	ATF_REQUIRE_EQ(3u, yangh_schema.nmod);
	ATF_REQUIRE((sh = module("shapes")) != NULL);
	ATF_REQUIRE((sys = module("ietf-system")) != NULL);
	ATF_REQUIRE(module("ietf-sid-file") != NULL);
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
	ATF_CHECK_STREQ("../id", yangh_schema.xpath[n->type->path]);
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
	if (n->nmap > 0 && n->map == NULL)
		(*dense)++;
	else if (n->nmap > 0)
		(*mapped)++;
	for (uint32_t i = 0; i < n->nchild; i++) {
		ATF_CHECK_MSG(cbl_ynode_child(n, (int64_t)(n->child[i]->sid -
		    n->sid)) == n->child[i], "%s/%s", n->name,
		    n->child[i]->name);
		check_lookup(n->child[i], dense, mapped);
	}
	for (uint32_t off = 0; n->map != NULL && off < n->nmap; off++)
		if (n->map[off] == 0)
			ATF_CHECK(cbl_ynode_child(n, (int64_t)
			    (n->child[0]->sid + off - n->sid)) == NULL);
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
	return (atf_no_error());
}
