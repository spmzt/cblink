/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * YANG patterns (cbl_pattern.c): XSD's regular expressions as POSIX
 * EREs.  The translations of the awkward cases; the types of RFC 9911
 * (and RFC 6991's zone with \p{N}\p{L}) against good and bad values;
 * every pattern of Arcana's YANG corpus compiling; and what is refused.
 */

#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "cbl_pattern.h"

static void
check_ere(const char *xsd, const char *want)
{
	char why[256], *got;
	size_t pos;

	got = cbl_pattern_ere(xsd, why, sizeof(why), &pos);
	ATF_REQUIRE_MSG(got != NULL, "%s: %s at %zu", xsd, why, pos);
	ATF_CHECK_STREQ_MSG(want, got, "%s", xsd);
	free(got);
}

/* Every good value matches, every bad one does not. */
static void
check_values(const char *xsd, const char *const *good,
    const char *const *bad)
{
	regex_t re;
	char why[256];
	size_t pos;

	ATF_REQUIRE_MSG(cbl_pattern_compile(xsd, &re, why, sizeof(why),
	    &pos) == 0, "%s: %s at %zu", xsd, why, pos);
	for (; *good != NULL; good++)
		ATF_CHECK_MSG(cbl_pattern_match(&re, *good), "%s should match "
		    "%s", *good, xsd);
	for (; *bad != NULL; bad++)
		ATF_CHECK_MSG(!cbl_pattern_match(&re, *bad), "%s should not "
		    "match %s", *bad, xsd);
	cbl_pattern_free(&re);
}

static void
check_refused(const char *xsd, size_t wantpos, const char *wantwhy)
{
	char why[256], *ere;
	size_t pos = 999;

	ere = cbl_pattern_ere(xsd, why, sizeof(why), &pos);
	ATF_CHECK_MSG(ere == NULL, "%s translated to %s", xsd, ere);
	free(ere);
	ATF_CHECK_EQ_MSG(wantpos, pos, "%s: at %zu (%s)", xsd, pos, why);
	ATF_CHECK_MSG(strstr(why, wantwhy) != NULL, "%s: %s", xsd, why);
}

ATF_TC_WITHOUT_HEAD(translate);
ATF_TC_BODY(translate, tc)
{

	/* Anchored; "^" and "$" are XSD's ordinary characters. */
	check_ere("abc", "^(abc)$");
	check_ere("a^b$", "^(a\\^b\\$)$");
	/* "." stops at a newline or a carriage return. */
	check_ere("a.b", "^(a[^\n\r]b)$");
	/* Escapes, outside a class. */
	check_ere("\\.\\-\\^\\\\\\|\\(\\)\\[\\]\\{\\}\\?\\*\\+",
	    "^(\\.-\\^\\\\\\|\\(\\)\\[]\\{}\\?\\*\\+)$");
	check_ere("\\n\\r\\t", "^(\n\r\t)$");
	/* Multi-character escapes and their complements. */
	check_ere("\\d\\D", "^([[:digit:]][^[:digit:]])$");
	check_ere("\\s\\S", "^([ \t\n\r][^ \t\n\r])$");
	check_ere("\\w", "^([[:alnum:]$+<=>`|~^])$");
	check_ere("\\W", "^([^[:alnum:]$+<=>`|~^])$");
	check_ere("\\i\\c", "^([[:alpha:]_:][[:alnum:]._:-])$");
	check_ere("\\p{L}\\p{Lu}\\p{Ll}\\p{N}\\p{Nd}\\P{L}",
	    "^([[:alpha:]][[:upper:]][[:lower:]][[:digit:]][[:digit:]]"
	    "[^[:alpha:]])$");
	/* Classes rebuilt for POSIX: "]" first, "-" last, "^" not first. */
	check_ere("[\\]a]", "^([]a])$");
	check_ere("[\\^a]", "^([a^])$");
	check_ere("[\\^]", "^(\\^)$");
	check_ere("[\\^\\-]", "^([-^])$");
	check_ere("[^\\^]", "^([^^])$");
	check_ere("[-a]", "^([a-])$");
	check_ere("[a-]", "^([a-])$");
	check_ere("[a\\-z]", "^([az-])$");
	check_ere("[\\[a]", "^([a[])$");
	check_ere("[\\[\\]\\^\\-a]", "^([]a[^-])$");
	check_ere("[A-Za-z0-9\\-\\._~/]", "^([A-Za-z0-9._~/-])$");
	check_ere("[\\da-fA-F]", "^([[:digit:]a-fA-F])$");
	/* A range from a special character: one by one. */
	check_ere("[+--]", "^([+,-])$");
	/* Quantifiers, groups, alternation; an empty branch kept. */
	check_ere("(ab){2,5}c{3}d{1,}e?f*g+", "^((ab){2,5}c{3}d{1,}e?f*g+)$");
	check_ere("a|", "^(a|())$");
	/* Taken no times: an empty group, which regcomp(3) takes. */
	check_ere("ab{0}c[x]{0,0}(d){0}", "^(a()c()())$");
	check_ere("b{0,}", "^(b{0,})$");
	check_ere("()", "^((()))$");
	check_ere("", "^(())$");
	/* UTF-8 passes through. */
	check_ere("caf\xc3\xa9[\xc3\xa0-\xc3\xbf]+",
	    "^(caf\xc3\xa9[\xc3\xa0-\xc3\xbf]+)$");
}

ATF_TC_WITHOUT_HEAD(rfc9911);
ATF_TC_BODY(rfc9911, tc)
{
	/* ietf-inet-types@2025-12-22, ipv4-address. */
	static const char *const v4g[] = { "0.0.0.0", "192.0.2.1",
	    "255.255.255.255", "192.0.2.1%eth0", NULL };
	static const char *const v4b[] = { "256.0.0.1", "1.2.3", "01.2.3.4x",
	    "1.2.3.4.5", "1.2.3.4%", " 1.2.3.4", NULL };
	/* ipv6-address, both its patterns. */
	static const char *const v6g[] = { "::", "::1", "2001:db8::1",
	    "fe80::1%em0", "2001:db8:0:0:0:0:2:1", "::ffff:192.0.2.1",
	    NULL };
	static const char *const v6b[] = { "2001:db8::g", "1.2.3.4", "",
	    NULL };
	static const char *const v6bb[] = { "abc", "1.2.3.4", NULL };
	static const char *const macg[] = { "00:1b:21:aa:BB:0f", NULL };
	static const char *const macb[] = { "00:1b:21:aa:bb", "001b21aabb0f",
	    "00-1b-21-aa-bb-0f", "00:1b:21:aa:bb:0g", NULL };
	static const char *const dtg[] = { "2026-10-13T20:01:02Z",
	    "2026-10-13T20:01:02.123+02:00", "2016-12-31T23:59:60Z",
	    "2026-10-13T20:01:02", NULL };
	static const char *const dtb[] = { "2026-13-13T20:01:02Z",
	    "2026-10-13 20:01:02Z", "2026-10-13T24:01:02Z",
	    "2026-10-13T20:01:02+15:00", NULL };
	static const char *const uuidg[] = {
	    "f81d4fae-7dec-11d0-a765-00a0c91e6bf6", NULL };
	static const char *const uuidb[] = {
	    "f81d4fae7dec11d0a76500a0c91e6bf6",
	    "f81d4fae-7dec-11d0-a765-00a0c91e6bfx", NULL };
	static const char *const dng[] = { "example.org", "example.org.", ".",
	    "a.b-c.d_e", "_sip._udp.example.org", NULL };
	static const char *const dnb[] = { "-a.example", "a..b", "a b",
	    "example.org-", NULL };

	check_values("(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.)"
	    "{3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(%.+)?",
	    v4g, v4b);
	check_values("((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-f"
	    "A-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?"
	    "[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))(%[A-"
	    "Za-z0-9][A-Za-z0-9\\-\\._~/]*)?", v6g, v6b);
	check_values("(([^:]+:){6}(([^:]+:[^:]+)|(.*\\..*)))|((([^:]+:)*[^:]+)?"
	    "::(([^:]+:)*[^:]+)?)(%.+)?", v6g, v6bb);
	check_values("[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", macg, macb);
	check_values("[0-9]{4}-(1[0-2]|0[1-9])-(0[1-9]|[1-2][0-9]|3[0-1])T(0["
	    "0-9]|1[0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)(\\.[0-9]+)?(Z|[\\+"
	    "\\-]((1[0-3]|0[0-9]):([0-5][0-9])|14:00))?", dtg, dtb);
	check_values("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]"
	    "{4}-[0-9a-fA-F]{12}", uuidg, uuidb);
	check_values("((([a-zA-Z0-9_]([a-zA-Z0-9\\-_]){0,61})?[a-zA-Z0-9]\\.)*"
	    "([a-zA-Z0-9_]([a-zA-Z0-9\\-_]){0,61})?[a-zA-Z0-9]\\.?)|\\.", dng,
	    dnb);
}

ATF_TC_WITHOUT_HEAD(unicode);
ATF_TC_BODY(unicode, tc)
{
	/*
	 * RFC 6991's ipv4-address: a zone of Unicode letters and digits.
	 * "²" is \p{No}, a number but no digit: [:digit:] has it not, the
	 * narrowing cbl_pattern.c says \p{N} has.
	 */
	static const char *const zg[] = { "192.0.2.1%eth0",
	    "192.0.2.1%\xc3\xa9th0", "192.0.2.1%\xe4\xb8\xad\xd9\xa3", NULL };
	static const char *const zb[] = { "192.0.2.1%eth-0", "192.0.2.1%",
	    "192.0.2.1%\xc2\xb2", NULL };
	/* "." is one character, not one byte; \s is XSD's four. */
	static const char *const dg[] = { "\xc3\xa9", "a", NULL };
	static const char *const db[] = { "\n", "\xc3\xa9\xc3\xa9", "", NULL };
	static const char *const sg[] = { " ", "\t", "\n", "\r", NULL };
	static const char *const sb[] = { "\xe2\x80\x83", "\v", NULL };
	static const char *const wg[] = { "a", "\xc3\xa9", "7", "$", "+",
	    NULL };
	static const char *const wb[] = { ".", "-", " ", "_", NULL };

	check_values("(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.)"
	    "{3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(%[\\p{N}"
	    "\\p{L}]+)?", zg, zb);
	check_values(".", dg, db);
	check_values("\\s", sg, sb);
	check_values("\\w", wg, wb);
}

/* Every pattern of Arcana's YANG corpus (share/yang), as compiled. */
ATF_TC_WITHOUT_HEAD(corpus);
ATF_TC_BODY(corpus, tc)
{
	static const char *const pats[] = {
#include "pattern_corpus.h"
	};
	regex_t re;
	char why[256];
	size_t pos;

	for (size_t i = 0; i < sizeof(pats) / sizeof(pats[0]); i++) {
		ATF_CHECK_MSG(cbl_pattern_compile(pats[i], &re, why,
		    sizeof(why), &pos) == 0, "%s: %s at %zu", pats[i], why,
		    pos);
		cbl_pattern_free(&re);
	}
}

ATF_TC_WITHOUT_HEAD(refused);
ATF_TC_BODY(refused, tc)
{
	char *big;

	check_refused("[a-z-[aeiou]]", 4, "class subtraction");
	check_refused("\\p{IsBasicLatin}", 0, "block escape");
	check_refused("\\p{Sm}", 0, "the category \\p{Sm}");
	check_refused("\\p{Lo}", 0, "the category \\p{Lo}");
	check_refused("\\p{L", 0, "without {category}");
	check_refused("(a)\\1", 3, "no back-references");
	check_refused("\\x", 0, "not an XSD escape");
	check_refused("[\\D]", 1, "complemented escape inside a class");
	check_refused("[\\P{L}a]", 1, "complemented escape inside a class");
	check_refused("a{256}", 1, "count over");
	check_refused("a{2,1}", 1, "backwards");
	check_refused("a{", 1, "not opening a count");
	check_refused("a{2", 1, "without its \"}\"");
	check_refused("*a", 0, "nothing before it");
	check_refused("a]", 1, "unescaped \"]\"");
	check_refused("a}", 1, "unescaped \"}\"");
	check_refused("(a", 0, "without its \")\"");
	check_refused("a)", 1, "closes no group");
	check_refused("[a", 0, "without its \"]\"");
	check_refused("[]", 1, "empty class");
	check_refused("[a[b]", 2, "unescaped \"[\"");
	check_refused("[a-c-e]", 4, "\"-\" that is not");
	check_refused("[z-a]", 2, "backwards");
	check_refused("[a-\\d]", 2, "range to a class escape");
	check_refused("a\\", 1, "backslash at the end");
	check_refused("a\xff", 1, "not UTF-8");
	check_refused("\xc3(", 0, "not UTF-8");
	check_refused("((((((((((((((((((((((((((((((((((a))))))))))))))))))))"
	    "))))))))))))))", 32, "deeper than");
	big = malloc(CBL_PAT_MAX_LEN + 2);
	ATF_REQUIRE(big != NULL);
	memset(big, 'a', CBL_PAT_MAX_LEN + 1);
	big[CBL_PAT_MAX_LEN + 1] = '\0';
	check_refused(big, 0, "longer than");
	free(big);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, translate);
	ATF_TP_ADD_TC(tp, rfc9911);
	ATF_TP_ADD_TC(tp, unicode);
	ATF_TP_ADD_TC(tp, corpus);
	ATF_TP_ADD_TC(tp, refused);
	return (atf_no_error());
}
