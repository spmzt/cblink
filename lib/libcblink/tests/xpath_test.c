/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The XPath 1.0 parser (cbl_xpath.c): YANG's expressions, the lexical
 * disambiguation of XPath section 3.7, every axis and node test, the
 * printed form parsed again to the same, errors with their offsets, and
 * the bounds on depth and length.
 */

#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "cbl_xpath.h"

static char *
printed(const struct cbl_xp *x)
{
	char *s = NULL;
	size_t len;
	FILE *fp;

	ATF_REQUIRE((fp = open_memstream(&s, &len)) != NULL);
	cbl_xp_print(x, fp);
	ATF_REQUIRE(fclose(fp) == 0);
	return (s);
}

/* Parse, print, parse the print and print again: the two prints agree. */
static char *
round_trip(const char *expr)
{
	struct cbl_xp *x, *y;
	char err[128], *a, *b;
	size_t pos;

	x = cbl_xp_parse(expr, err, sizeof(err), &pos);
	ATF_REQUIRE_MSG(x != NULL, "%s: %s at %zu", expr, err, pos);
	a = printed(x);
	y = cbl_xp_parse(a, err, sizeof(err), &pos);
	ATF_REQUIRE_MSG(y != NULL, "%s printed as %s: %s at %zu", expr, a,
	    err, pos);
	b = printed(y);
	ATF_CHECK_STREQ_MSG(a, b, "%s", expr);
	cbl_xp_free(x);
	cbl_xp_free(y);
	free(b);
	return (a);
}

static void
check_print(const char *expr, const char *want)
{
	char *got;

	got = round_trip(expr);
	ATF_CHECK_STREQ_MSG(want, got, "%s", expr);
	free(got);
}

static void
check_error(const char *expr, size_t wantpos, const char *wantmsg)
{
	char err[128];
	size_t pos = 999;

	ATF_CHECK_MSG(cbl_xp_parse(expr, err, sizeof(err), &pos) == NULL,
	    "%s parsed", expr);
	ATF_CHECK_EQ_MSG(wantpos, pos, "%s: at %zu (%s)", expr, pos, err);
	ATF_CHECK_MSG(strstr(err, wantmsg) != NULL, "%s: %s", expr, err);
}

ATF_TC_WITHOUT_HEAD(yang);
ATF_TC_BODY(yang, tc)
{

	/* As the IETF modules write them. */
	check_print("derived-from-or-self(../type, 'rt:static')",
	    "derived-from-or-self(parent::node()/child::type, 'rt:static')");
	check_print("/if:interfaces/if:interface/if:name",
	    "/child::if:interfaces/child::if:interface/child::if:name");
	check_print("../../../rt:address-family = 'v4ur:ipv4-unicast'",
	    "parent::node()/parent::node()/parent::node()/child::rt:address-family = 'v4ur:ipv4-unicast'");
	check_print("not(../lower-port) or ../lower-port <= ../upper-port",
	    "not(parent::node()/child::lower-port) or parent::node()/child::lower-port <= parent::node()/child::upper-port");
	check_print("deref(.)/../interface",
	    "deref(self::node())/parent::node()/child::interface");
	check_print("/nacm:nacm/nacm:groups/nacm:group[nacm:name = current()]",
	    "/child::nacm:nacm/child::nacm:groups/child::nacm:group[child::nacm:name = current()]");
	check_print("count(../address) > 0 and re-match(., '[a-z]+')",
	    "count(parent::node()/child::address) > 0 and re-match(self::node(), '[a-z]+')");
	check_print("enum-value(../state) = 2 or bit-is-set(../flags, \"up\")",
	    "enum-value(parent::node()/child::state) = 2 or bit-is-set(parent::node()/child::flags, 'up')");
}

ATF_TC_WITHOUT_HEAD(disambiguation);
ATF_TC_BODY(disambiguation, tc)
{

	/* "*": a name test where a step starts, multiplication elsewhere. */
	check_print("* * *",
	    "child::* * child::*");
	check_print("a*b",
	    "child::a * child::b");
	check_print("x:*", "child::x:*");
	/* An operator name after an operand, a name test elsewhere. */
	check_print("and and and",
	    "child::and and child::and");
	check_print("div div div",
	    "child::div div child::div");
	check_print("mod mod 2",
	    "child::mod mod 2");
	/* A name with '-' and '.' in it, and a subtraction. */
	check_print("a-b - c",
	    "child::a-b - child::c");
	check_print("a.b", "child::a.b");
	/* A name before '(' is a function, before '::' an axis. */
	check_print("text()", "child::text()");
	check_print("count (x)", "count(child::x)");
	check_print("self :: x", "self::x");
	/* Unary minus, nested. */
	check_print("--1",
	    "--1");
	check_print("1 - -1",
	    "1 - -1");
	/* Precedence and associativity. */
	check_print("1 + 2 * 3 - 4",
	    "1 + 2 * 3 - 4");
	check_print("a or b and c = d < e + f * g | h",
	    "child::a or child::b and child::c = child::d < child::e + child::f * child::g | child::h");
	/* Numbers. */
	check_print(".5 + 1. + 12.25",
	    ".5 + 1. + 12.25");
	/* Variables, prefixed or not. */
	check_print("$USER = $a:b",
	    "$USER = $a:b");
	/* Literals with the other quote inside. */
	check_print("\"it's\"", "\"it's\"");
	check_print("'say \"x\"'", "'say \"x\"'");
}

/* The tree's shape, where the print no longer shows it. */
ATF_TC_WITHOUT_HEAD(shape);
ATF_TC_BODY(shape, tc)
{
	struct cbl_xp *x;

	/* (1 + (2 * 3)) - 4 */
	ATF_REQUIRE((x = cbl_xp_parse("1 + 2 * 3 - 4", NULL, 0, NULL)) !=
	    NULL);
	ATF_CHECK_EQ(CBL_XP_SUB, x->kind);
	ATF_CHECK_EQ(CBL_XP_ADD, x->args[0]->kind);
	ATF_CHECK_EQ(CBL_XP_MUL, x->args[0]->args[1]->kind);
	ATF_CHECK_EQ(CBL_XP_NUMBER, x->args[1]->kind);
	cbl_xp_free(x);
	/* a or (b and (c = d)) */
	ATF_REQUIRE((x = cbl_xp_parse("a or b and c = d", NULL, 0, NULL)) !=
	    NULL);
	ATF_CHECK_EQ(CBL_XP_OR, x->kind);
	ATF_CHECK_EQ(CBL_XP_AND, x->args[1]->kind);
	ATF_CHECK_EQ(CBL_XP_EQ, x->args[1]->args[1]->kind);
	cbl_xp_free(x);
	/* -(-(1)), and 1 - (-(1)) */
	ATF_REQUIRE((x = cbl_xp_parse("1 - -1", NULL, 0, NULL)) != NULL);
	ATF_CHECK_EQ(CBL_XP_SUB, x->kind);
	ATF_CHECK_EQ(CBL_XP_NEG, x->args[1]->kind);
	cbl_xp_free(x);
	/* a | (b | c), kept as written */
	check_print("a | (b | c)", "child::a | (child::b | child::c)");
	check_print("(a or b) and c", "(child::a or child::b) and child::c");
	check_print("1 - (2 - 3)", "1 - (2 - 3)");
	check_print("-(1 + 2)", "-(1 + 2)");
	/* A filter over a path, and over a union. */
	check_print("(a/b)[1]", "(child::a/child::b)[1]");
	check_print("(a | b)/c", "(child::a | child::b)/child::c");
}

ATF_TC_WITHOUT_HEAD(paths);
ATF_TC_BODY(paths, tc)
{

	check_print("/", "/");
	check_print("//a", "/descendant-or-self::node()/child::a");
	check_print("a//b", "child::a/descendant-or-self::node()/child::b");
	check_print(".", "self::node()");
	check_print("..", "parent::node()");
	check_print("@id", "attribute::id");
	check_print("ancestor-or-self::node()[1]",
	    "ancestor-or-self::node()[1]");
	check_print("following-sibling::*[position() = last()]",
	    "following-sibling::*[position() = last()]");
	check_print("preceding::comment()", "preceding::comment()");
	check_print("namespace::x | descendant::y | preceding-sibling::z",
	    "namespace::x | descendant::y | preceding-sibling::z");
	check_print("processing-instruction('pi')",
	    "child::processing-instruction('pi')");
	check_print("ancestor::a | following::b",
	    "ancestor::a | following::b");
	/* A filter, and a path from it. */
	check_print("(a | b)[1]",
	    "(child::a | child::b)[1]");
	check_print("deref(.)//x",
	    "deref(self::node())/descendant-or-self::node()/child::x");
	check_print("(/a)[1]/b",
	    "(/child::a)[1]/child::b");
	/* Predicates on predicates. */
	check_print("a[b[c = 1]][2]",
	    "child::a[child::b[child::c = 1]][2]");
}

ATF_TC_WITHOUT_HEAD(errors);
ATF_TC_BODY(errors, tc)
{

	check_error("", 0, "expression expected");
	check_error("a +", 3, "expression expected");
	check_error("a b", 2, "operator expected");
	check_error("(a", 2, "')' expected");
	check_error("a[1", 3, "']' expected");
	check_error("f(a,)", 4, "expression expected");
	check_error("'abc", 0, "unterminated literal");
	check_error("a ! b", 2, "'!' not followed");
	check_error("a : b", 2, "':' alone");
	check_error("nope::a", 0, "no axis");
	check_error("x:y::a", 0, "prefixed axis");
	check_error("child::(a)", 7, "node test expected");
	check_error("a ^ b", 2, "unexpected character");
	check_error("$", 0, "'$' not followed");
	check_error("1 2", 2, "unexpected text");
	check_error("a)", 1, "unexpected text");
}

static void
check_lite(const char *expr, bool want, const char *wantwhy)
{
	struct cbl_xp *x;
	char why[128];
	size_t pos;
	bool ok;

	ATF_REQUIRE_MSG((x = cbl_xp_parse(expr, NULL, 0, NULL)) != NULL,
	    "%s", expr);
	ok = cbl_xp_lite(x, why, sizeof(why), &pos);
	ATF_CHECK_MSG(ok == want, "%s: %s", expr, ok ? "within" : why);
	if (!ok && wantwhy != NULL)
		ATF_CHECK_MSG(strstr(why, wantwhy) != NULL, "%s: %s", expr,
		    why);
	cbl_xp_free(x);
}

ATF_TC_WITHOUT_HEAD(lite);
ATF_TC_BODY(lite, tc)
{

	/* What the IETF modules write. */
	check_lite("derived-from-or-self(../type, 'rt:static')", true, NULL);
	check_lite("/nw:networks/nw:network[nw:network-id = "
	    "current()/../network-ref]/nw:node/nw:node-id", true, NULL);
	check_lite(". = 'pre-shared' or . = 'eap'", true, NULL);
	check_lite("count(../address) > 0 and not(../x)", true, NULL);
	check_lite("deref(.)/../interface", true, NULL);
	check_lite("re-match(., '[a-z]+') and string-length(.) < 64 and "
	    "concat(a, b, c) != substring(d, 1, 2)", true, NULL);
	check_lite("enum-value(../s) + 1 >= 2 and bit-is-set(../f, 'up')",
	    true, NULL);
	check_lite("//x[y] | ../z[not(w)]", true, NULL);
	check_lite("-1 * 2 div 3 mod 4", true, NULL);
	/* Outside. */
	check_lite("position() = 1", false, "the function position()");
	check_lite("x[1]", false, "not a condition");
	check_lite("x[last() - 1]", false, "not a condition");
	check_lite("ancestor::x", false, "the axis ancestor");
	check_lite("following-sibling::x", false, "the axis");
	check_lite("@id", false, "the axis attribute");
	check_lite("x/text()", false, "node test");
	check_lite("$USER = 'a'", false, "a variable");
	check_lite("(a | b)[x]", false, "a predicate on an expression");
	check_lite("concat(a)", false, "concat() with 1 arguments");
	check_lite("not()", false, "not() with 0 arguments");
	check_lite("rt:foo(.)", false, "the function rt:foo()");
	check_lite("string(.)/x", false, "a path from an expression");
	check_lite("sum(x) > 1", false, "the function sum()");
	/* Deep inside, still found. */
	check_lite("a[b[c[position() = 1]]]", false, "position()");
}

ATF_TC_WITHOUT_HEAD(bounds);
ATF_TC_BODY(bounds, tc)
{
	char *e;
	size_t n = CBL_XP_MAX_DEPTH + 10;
	struct cbl_xp *x;
	char err[128];

	/* Nested parentheses and minus signs beyond the depth bound. */
	e = calloc(2 * n + 2, 1);
	ATF_REQUIRE(e != NULL);
	memset(e, '(', n);
	e[n] = '1';
	memset(e + n + 1, ')', n);
	ATF_CHECK(cbl_xp_parse(e, err, sizeof(err), NULL) == NULL);
	ATF_CHECK(strstr(err, "nested too deep") != NULL);
	memset(e, '-', n);
	e[n] = '1';
	e[n + 1] = '\0';
	ATF_CHECK(cbl_xp_parse(e, err, sizeof(err), NULL) == NULL);
	ATF_CHECK(strstr(err, "nested too deep") != NULL);
	free(e);
	/* Within it, fine. */
	ATF_REQUIRE((x = cbl_xp_parse("((((1))))", NULL, 0, NULL)) != NULL);
	cbl_xp_free(x);
	/* A long chain of steps is not nesting. */
	e = calloc(4 * 1000 + 1, 1);
	ATF_REQUIRE(e != NULL);
	for (size_t i = 0; i < 1000; i++)
		memcpy(e + 4 * i, "/abc", 4);
	ATF_REQUIRE((x = cbl_xp_parse(e, NULL, 0, NULL)) != NULL);
	ATF_CHECK_EQ(1000, x->nargs);
	cbl_xp_free(x);
	free(e);
	/* A chain of operators taller than the height bound. */
	e = calloc(4 * (CBL_XP_MAX_HEIGHT + 10) + 2, 1);
	ATF_REQUIRE(e != NULL);
	strcpy(e, "1");
	for (size_t i = 0; i < CBL_XP_MAX_HEIGHT + 10; i++)
		strcat(e, " + 1");
	ATF_CHECK(cbl_xp_parse(e, err, sizeof(err), NULL) == NULL);
	ATF_CHECK(strstr(err, "in a row") != NULL);
	free(e);
	/* Longer than the length bound. */
	e = calloc(CBL_XP_MAX_LEN + 2, 1);
	ATF_REQUIRE(e != NULL);
	memset(e, 'a', CBL_XP_MAX_LEN + 1);
	ATF_CHECK(cbl_xp_parse(e, err, sizeof(err), NULL) == NULL);
	ATF_CHECK(strstr(err, "longer than") != NULL);
	free(e);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, yang);
	ATF_TP_ADD_TC(tp, disambiguation);
	ATF_TP_ADD_TC(tp, shape);
	ATF_TP_ADD_TC(tp, paths);
	ATF_TP_ADD_TC(tp, errors);
	ATF_TP_ADD_TC(tp, lite);
	ATF_TP_ADD_TC(tp, bounds);
	return (atf_no_error());
}
