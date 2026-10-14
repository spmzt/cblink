/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The static validator (cbl_yvalidate()) on the module rules, a rule a
 * case, most from RFC 7950's own examples: a valid instance first, then
 * each rule broken, and what the error says: the node, the error-tag,
 * the error-app-tag.
 */

#include <atf-c.h>
#include <errno.h>
#include <string.h>

#include "rules.h"

static const struct cbl_ynode *n_rules;

static const struct cbl_ynode *
top(const char *name)
{
	const struct cbl_ymodule *m = rules_schema.mod[0];

	for (uint32_t i = 0; i < m->ntop; i++)
		if (strcmp(m->top[i]->name, name) == 0)
			return (m->top[i]);
	atf_tc_fail("no %s", name);
}

static uint64_t
ident(const char *name)
{

	for (uint32_t i = 0; i < rules_schema.nident; i++)
		if (strcmp(rules_schema.ident[i].name, name) == 0)
			return (rules_schema.ident[i].sid);
	atf_tc_fail("no identity %s", name);
}

static const char *const one_tag[] = { "a" };

/* What is valid: the mandatory leaf, a snack, a tag. */
static void
valid(struct rules_rules *r)
{

	n_rules = top("rules");
	memset(r, 0, sizeof(*r));
	r->must_have = "x";
	r->snack = RULES_RULES_SNACK_SPORTS_ARENA;
	r->pretzel = true;
	r->tag.n = 1;
	r->tag.v = one_tag;
}

/* r is refused: the node named, its tag and app-tag. */
static void
refused(const struct rules_rules *r, int flags, const char *node,
    const char *tag, const char *apptag)
{
	struct cbl_yverr e;

	ATF_REQUIRE_EQ_MSG(EINVAL, cbl_yvalidate(n_rules, r, flags, &e),
	    "%s: accepted", node);
	ATF_CHECK_STREQ_MSG(node, e.node->name, "%s", e.msg);
	ATF_CHECK_STREQ_MSG(tag, e.tag, "%s", e.msg);
	if (apptag == NULL)
		ATF_CHECK_MSG(e.apptag == NULL, "%s: app-tag %s", e.msg,
		    e.apptag);
	else
		ATF_CHECK_STREQ_MSG(apptag, e.apptag != NULL ? e.apptag : "",
		    "%s", e.msg);
}

static void
accepted(const struct rules_rules *r, int flags)
{
	struct cbl_yverr e;

	ATF_CHECK_EQ_MSG(0, cbl_yvalidate(n_rules, r, flags, &e), "%s",
	    e.msg);
}

ATF_TC_WITHOUT_HEAD(valid);
ATF_TC_BODY(valid, tc)
{
	struct rules_rules r;
	struct rules d = { .rules = &r };
	struct cbl_yverr e;

	valid(&r);
	accepted(&r, 0);
	accepted(&r, CBL_YV_EDIT);
	/* As a module's top-level node, in its data struct. */
	ATF_CHECK_EQ(0, cbl_yvalidate_member(n_rules, &d, 0, &e));
}

/* RFC 7950 section 9.2.5: range "1..4 | 10..20"; decimal64 scaled. */
ATF_TC_WITHOUT_HEAD(ranges);
ATF_TC_BODY(ranges, tc)
{
	static const int32_t ok[] = { 1, 4, 10, 20 }, bad[] = { 0, 5, 9, 21 };
	struct rules_rules r;

	valid(&r);
	r.has_small = true;
	for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
		r.small = ok[i];
		accepted(&r, 0);
	}
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		r.small = bad[i];
		refused(&r, 0, "small", "invalid-value", NULL);
	}
	valid(&r);
	r.has_ratio = true;
	r.ratio = 100;			/* 1.00 */
	accepted(&r, 0);
	r.ratio = -101;			/* -1.01 */
	refused(&r, 0, "ratio", "invalid-value", NULL);
}

/* Lengths in characters, not bytes; a binary's in bytes. */
ATF_TC_WITHOUT_HEAD(lengths);
ATF_TC_BODY(lengths, tc)
{
	static const uint8_t four[] = { 1, 2, 3, 4 };
	struct rules_rules r;

	valid(&r);
	r.code = "\xc3\xa9\xc3\xa9";	/* "éé": two characters, four bytes */
	accepted(&r, 0);
	r.code = "abc";
	refused(&r, 0, "code", "invalid-value", NULL);
	r.code = "\xc3";		/* not UTF-8 */
	refused(&r, 0, "code", "invalid-value", NULL);
	valid(&r);
	r.blob.p = four;
	r.blob.len = 4;
	accepted(&r, 0);
	r.blob.len = 3;
	refused(&r, 0, "blob", "invalid-value", NULL);
	valid(&r);
	r.host_name = "";
	refused(&r, 0, "host-name", "invalid-value", NULL);
}

/* RFC 7950 section 9.4.7's pattern, its error-app-tag; invert-match. */
ATF_TC_WITHOUT_HEAD(patterns);
ATF_TC_BODY(patterns, tc)
{
	struct rules_rules r;
	struct cbl_yverr e;

	valid(&r);
	r.host_name = "www.example.org";
	accepted(&r, 0);
	r.host_name = "www example";
	refused(&r, 0, "host-name", "invalid-value", "bad-host");
	ATF_REQUIRE_EQ(EINVAL, cbl_yvalidate(n_rules, &r, 0, &e));
	ATF_CHECK_STREQ("not a host name", e.msg);
	valid(&r);
	r.not_x = "yes";
	accepted(&r, 0);
	r.not_x = "xyes";
	refused(&r, 0, "not-x", "invalid-value", NULL);
}

ATF_TC_WITHOUT_HEAD(enums_bits);
ATF_TC_BODY(enums_bits, tc)
{
	static const uint8_t up_down[] = { 0x09 }, other[] = { 0x02 };
	struct rules_rules r;

	valid(&r);
	r.has_colour = true;
	r.colour = RULES_RULES_COLOUR_GREEN;
	accepted(&r, 0);
	r.colour = (enum rules_rules_colour)3;
	refused(&r, 0, "colour", "invalid-value", NULL);
	valid(&r);
	r.flags.p = up_down;
	r.flags.len = 1;
	accepted(&r, 0);
	r.flags.p = other;		/* position 1: no such bit */
	refused(&r, 0, "flags", "invalid-value", NULL);
}

/* RFC 7950 section 9.10: derived from the base; not the base itself. */
ATF_TC_WITHOUT_HEAD(identities);
ATF_TC_BODY(identities, tc)
{
	struct rules_rules r;

	valid(&r);
	r.has_alg = true;
	r.alg = ident("des3");		/* des3 from des from crypto-alg */
	accepted(&r, 0);
	r.alg = ident("des");
	accepted(&r, 0);
	r.alg = ident("crypto-alg");
	refused(&r, 0, "alg", "invalid-value", NULL);
	r.alg = ident("sha1");
	refused(&r, 0, "alg", "invalid-value", NULL);
	r.alg = 12345;
	refused(&r, 0, "alg", "invalid-value", NULL);
}

/* A union: the member set, by its own type. */
ATF_TC_WITHOUT_HEAD(unions);
ATF_TC_BODY(unions, tc)
{
	struct rules_rules r;

	valid(&r);
	r.has_either = true;
	r.either.which = 0;
	r.either.v.m0 = 5;
	accepted(&r, 0);
	r.either.v.m0 = 50;
	refused(&r, 0, "either", "invalid-value", NULL);
	r.either.which = 1;
	r.either.v.m1 = "abc";
	accepted(&r, 0);
	r.either.v.m1 = "ABC";
	refused(&r, 0, "either", "invalid-value", NULL);
	r.either.which = 2;
	refused(&r, 0, "either", "invalid-value", NULL);
}

/* RFC 7950 section 7.9.6's snack: mandatory; one case only. */
ATF_TC_WITHOUT_HEAD(mandatory_choice);
ATF_TC_BODY(mandatory_choice, tc)
{
	struct rules_rules r;

	valid(&r);
	r.must_have = NULL;
	refused(&r, 0, "must-have", "missing-element", NULL);
	valid(&r);
	r.snack = RULES_RULES_SNACK_NONE;
	r.pretzel = false;
	refused(&r, 0, "beer", "data-missing", "missing-choice");
	valid(&r);
	r.has_chocolate = true;		/* late-night's, sports-arena given */
	refused(&r, 0, "chocolate", "bad-element", NULL);
	r.snack = RULES_RULES_SNACK_LATE_NIGHT;
	r.pretzel = false;
	accepted(&r, 0);
}

/* min-elements 1, max-elements 3; a configuration leaf-list's values. */
ATF_TC_WITHOUT_HEAD(counts);
ATF_TC_BODY(counts, tc)
{
	static const char *const four[] = { "a", "b", "c", "d" };
	static const char *const twice[] = { "a", "a" };
	struct rules_rules r;

	valid(&r);
	r.tag.n = 0;
	refused(&r, 0, "tag", "operation-failed", "too-few-elements");
	r.tag.v = four;
	r.tag.n = 3;
	accepted(&r, 0);
	r.tag.n = 4;
	refused(&r, 0, "tag", "operation-failed", "too-many-elements");
	r.tag.v = twice;
	r.tag.n = 2;
	refused(&r, 0, "tag", "data-exists", NULL);
}

/* Keys: there, each entry's own; RFC 7950 section 7.8.3's unique. */
ATF_TC_WITHOUT_HEAD(keys_unique);
ATF_TC_BODY(keys_unique, tc)
{
	struct rules_rules_server_addr a1 = { .ip = "10.0.0.1",
	    .has_port = true, .port = 80 }, a2 = a1, a3 = { .ip = "10.0.0.1" };
	struct rules_rules_server s[2] = {
		{ .name = "one", .addr = &a1 },
		{ .name = "two", .addr = &a2 },
	};
	struct rules_rules r;

	valid(&r);
	r.server.n = 2;
	r.server.v = s;
	refused(&r, 0, "server", "operation-failed", "data-not-unique");
	a2.port = 81;
	accepted(&r, 0);
	/* Only where all the unique leaves are. */
	s[1].addr = &a3;
	accepted(&r, 0);
	s[1].addr = NULL;
	accepted(&r, 0);
	s[1].name = "one";
	refused(&r, 0, "server", "data-exists", NULL);
	s[1].name = NULL;
	refused(&r, 0, "name", "missing-element", NULL);
}

/* config false: there in state, refused in an edit. */
ATF_TC_WITHOUT_HEAD(config_false);
ATF_TC_BODY(config_false, tc)
{
	struct rules_rules r;

	valid(&r);
	r.status = "up";
	accepted(&r, 0);
	refused(&r, CBL_YV_EDIT, "status", "invalid-value", NULL);
}

/*
 * Defaults, each kind from its canonical form; what is set stays, and a
 * choice's default case only where no case is given.
 */
ATF_TC_WITHOUT_HEAD(defaults);
ATF_TC_BODY(defaults, tc)
{
	struct rules_rules_defaults d = { 0 }, d2 = { .has_on = true,
	    .on = false, .transfer = RULES_RULES_DEFAULTS_TRANSFER_DAILY,
	    .daily = true };
	struct rules_rules r;
	cbl_yarena *a;

	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	valid(&r);
	r.defaults = &d;
	ATF_REQUIRE_EQ(0, cbl_ydefaults(n_rules, &r, a));
	ATF_CHECK(r.has_port && r.port == 80);
	ATF_CHECK_EQ(RULES_RULES_DEFAULTS_TRANSFER_INTERVAL, d.transfer);
	ATF_CHECK(d.has_interval && d.interval == 30);
	ATF_REQUIRE_EQ(2, d.dns.n);
	ATF_CHECK_STREQ("a.example", d.dns.v[0]);
	ATF_CHECK_STREQ("b.example", d.dns.v[1]);
	ATF_CHECK(d.has_hash_alg && d.hash_alg == ident("sha1"));
	ATF_CHECK(d.has_level && d.level == -1500);	/* -1.500 */
	/* fast at position 1, safe at 9: two bytes. */
	ATF_REQUIRE_EQ(2, d.mode.len);
	ATF_CHECK(((const uint8_t *)d.mode.p)[0] == 0x02 &&
	    ((const uint8_t *)d.mode.p)[1] == 0x02);
	ATF_CHECK(d.has_colour && d.colour == RULES_RULES_DEFAULTS_COLOUR_BLUE);
	ATF_REQUIRE_EQ(3, d.key_data.len);
	ATF_CHECK(memcmp(d.key_data.p, "\x01\x02\x03", 3) == 0);
	ATF_CHECK(d.has_on && d.on);
	ATF_CHECK_STREQ("anon", d.name);
	/* A union: the first member it is a value of, a string here. */
	ATF_CHECK(d.has_pick && d.pick.which == 1);
	ATF_CHECK_STREQ("word", d.pick.v.m1);
	accepted(&r, 0);

	/* What was set stays; daily's case given, no interval. */
	valid(&r);
	r.defaults = &d2;
	ATF_REQUIRE_EQ(0, cbl_ydefaults(n_rules, &r, a));
	ATF_CHECK(d2.has_on && !d2.on);
	ATF_CHECK_EQ(RULES_RULES_DEFAULTS_TRANSFER_DAILY, d2.transfer);
	ATF_CHECK(!d2.has_interval);
	/* An absent container stays absent. */
	valid(&r);
	ATF_REQUIRE_EQ(0, cbl_ydefaults(n_rules, &r, a));
	ATF_CHECK(r.defaults == NULL);
	cbl_yarena_free(a);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, valid);
	ATF_TP_ADD_TC(tp, ranges);
	ATF_TP_ADD_TC(tp, lengths);
	ATF_TP_ADD_TC(tp, patterns);
	ATF_TP_ADD_TC(tp, enums_bits);
	ATF_TP_ADD_TC(tp, identities);
	ATF_TP_ADD_TC(tp, unions);
	ATF_TP_ADD_TC(tp, mandatory_choice);
	ATF_TP_ADD_TC(tp, counts);
	ATF_TP_ADD_TC(tp, keys_unique);
	ATF_TP_ADD_TC(tp, config_false);
	ATF_TP_ADD_TC(tp, defaults);
	return (atf_no_error());
}
