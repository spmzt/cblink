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
#include <string.h>

#include <regex.h>

#include "yangh.h"

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

/* The identity of a SID, by a binary search of the table. */
static const struct cbl_yident *
ident(uint64_t sid)
{
	size_t lo = 0, hi = yangh_schema.nident;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (yangh_schema.ident[mid].sid == sid)
			return (&yangh_schema.ident[mid]);
		if (yangh_schema.ident[mid].sid < sid)
			lo = mid + 1;
		else
			hi = mid;
	}
	return (NULL);
}

/* derived-from(), and derived-from-or-self() with self. */
static bool
derived_from(uint64_t x, uint64_t base, bool self)
{
	const struct cbl_yident *b;
	size_t lo, hi;

	if (self && x == base)
		return (true);
	if ((b = ident(base)) == NULL)
		return (false);
	for (lo = 0, hi = b->nderived; lo < hi;) {
		size_t mid = lo + (hi - lo) / 2;

		if (b->derived[mid] == x)
			return (true);
		if (b->derived[mid] < x)
			lo = mid + 1;
		else
			hi = mid;
	}
	return (false);
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
		b = ident(t->bases[i]);
		ATF_CHECK_MSG(b != NULL, "base %ju not in the table",
		    (uintmax_t)t->bases[i]);
		if (b == NULL)
			continue;
		for (uint32_t j = 0; j < b->nderived; j++) {
			ATF_CHECK_MSG(ident(b->derived[j]) != NULL, "%s: "
			    "derived %ju not in the table", b->name,
			    (uintmax_t)b->derived[j]);
			if (j > 0)
				ATF_CHECK(b->derived[j] > b->derived[j - 1]);
			ATF_CHECK(derived_from(b->derived[j], b->sid, false));
			ATF_CHECK(!derived_from(b->sid, b->derived[j],
			    false));
		}
		ATF_CHECK(!derived_from(b->sid, b->sid, false));
		ATF_CHECK(derived_from(b->sid, b->sid, true));
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
	ATF_REQUIRE((colour = ident(UINT64_C(1099511727777))) != NULL);
	ATF_CHECK_STREQ("colour", colour->name);
	ATF_CHECK_STREQ("shapes", colour->module->name);
	ATF_REQUIRE((red = ident(UINT64_C(1099511727778))) != NULL);
	ATF_CHECK_STREQ("red", red->name);
	ATF_CHECK(derived_from(red->sid, colour->sid, false));
	ATF_CHECK(!derived_from(colour->sid, red->sid, true));
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
			ATF_CHECK(derived_from(yangh_schema.ident[i].sid,
			    m->sid, false));

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
	return (atf_no_error());
}
