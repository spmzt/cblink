/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Annotations (RFC 7952) on the instance tree (cbl_data.h), in YANG-CBOR
 * as draft-ietf-core-yang-metadata has them: its examples (section 3,
 * RFC 7952 section 5.2's), each written byte for byte as its figure,
 * with its SIDs (the test modules example-last-modified, mdex, foo and
 * bibliomod), and read back; the structs' decoder passing them over;
 * what is not one refused.  The figures' outer keys are deltas from
 * 61000; a tree's top is keyed by SIDs whole, as RFC 9254 has it.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "cbl_data.h"
#include "yangh.h"

#define	TS1	"2015-09-16T10:27:35+02:00"
#define	TS2	"2015-06-18T17:01:14+02:00"
/* Text of 25 bytes, its head and the bytes of TS1 and TS2 in hex. */
#define	H_TS1	"7819" "323031352d30392d31365431303a32373a33352b30323a3030"
#define	H_TS2	"7819" "323031352d30362d31385431373a30313a31342b30323a3030"
/* Tag 109 and its array of two. */
#define	H_META	"d86d82"

static const struct cbl_ymodule *
module(const char *name)
{

	for (uint32_t i = 0; i < yangh_schema.nmod; i++)
		if (strcmp(yangh_schema.mod[i]->name, name) == 0)
			return (yangh_schema.mod[i]);
	ATF_REQUIRE_MSG(false, "no module %s", name);
	return (NULL);
}

static const struct cbl_ynode *
top(const char *mod, const char *name)
{
	const struct cbl_ymodule *m = module(mod);

	for (uint32_t i = 0; i < m->ntop; i++)
		if (strcmp(m->top[i]->name, name) == 0)
			return (m->top[i]);
	ATF_REQUIRE_MSG(false, "no %s:%s", mod, name);
	return (NULL);
}

static const struct cbl_ynode *
child(const struct cbl_ynode *n, const char *name)
{

	for (uint32_t i = 0; i < n->nchild; i++)
		if (strcmp(n->child[i]->name, name) == 0)
			return (n->child[i]);
	ATF_REQUIRE_MSG(false, "%s: no %s", n->name, name);
	return (NULL);
}

static const struct cbl_yannot *
last_modified(void)
{
	const struct cbl_yannot *an;

	an = cbl_ymodule_annot(module("example-last-modified"),
	    "last-modified");
	ATF_REQUIRE(an != NULL);
	return (an);
}

static void
annotate(cbl_dnode *n, const char *when)
{

	ATF_REQUIRE_EQ(0, cbl_dnode_meta_set(n, last_modified(), &when));
}

static char *
hex(const struct cbl_ybuf *b)
{
	char *s;

	ATF_REQUIRE((s = malloc(b->len * 2 + 1)) != NULL);
	for (size_t i = 0; i < b->len; i++)
		snprintf(s + i * 2, 3, "%02x", b->p[i]);
	s[b->len * 2] = '\0';
	return (s);
}

static size_t
unhex(const char *h, uint8_t *out, size_t cap)
{
	size_t n = strlen(h) / 2;

	ATF_REQUIRE(n <= cap);
	for (size_t i = 0; i < n; i++) {
		unsigned v;

		ATF_REQUIRE_EQ(1, sscanf(h + i * 2, "%2x", &v));
		out[i] = (uint8_t)v;
	}
	return (n);
}

/*
 * Tree t written as want; read back strictly into another, which is
 * written the same; that other returned.
 */
static cbl_dtree *
same(cbl_dtree *t, const char *want)
{
	struct cbl_ybuf b = { 0 }, b2 = { 0 };
	uint8_t bytes[512];
	cbl_dtree *u;
	char why[256], *got;
	size_t n;

	ATF_REQUIRE_EQ(0, cbl_dtree_encode(t, &b));
	got = hex(&b);
	ATF_CHECK_STREQ(want, got);
	free(got);
	n = unhex(want, bytes, sizeof(bytes));
	ATF_REQUIRE((u = cbl_dtree_new(&yangh_schema)) != NULL);
	ATF_REQUIRE_EQ_MSG(0, cbl_dtree_decode(u, bytes, n, CBL_YD_STRICT,
	    why, sizeof(why)), "%s", why);
	ATF_REQUIRE_EQ(0, cbl_dtree_encode(u, &b2));
	got = hex(&b2);
	ATF_CHECK_STREQ(want, got);
	free(got);
	cbl_ybuf_free(&b);
	cbl_ybuf_free(&b2);
	cbl_dtree_free(t);
	return (u);
}

/* n's last-modified, read back. */
static void
check_when(const cbl_dnode *n, const char *want)
{
	const char *const *v;

	ATF_REQUIRE(n != NULL);
	v = cbl_dnode_meta(n, last_modified());
	ATF_REQUIRE_MSG(v != NULL, "%s: no annotation",
	    cbl_dnode_schema(n)->name);
	ATF_CHECK_STREQ(want, *v);
}

/* Figure 2: the container cask, annotated. */
ATF_TC_WITHOUT_HEAD(cask);
ATF_TC_BODY(cask, tc)
{
	const struct cbl_ynode *cask = top("mdex", "cask");
	uint16_t vintage = 2015;
	struct cbl_ybuf b = { 0 };
	cbl_dnode *c;
	cbl_dtree *t;
	char *got;

	ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
	ATF_REQUIRE_EQ(0, cbl_dnode_add(cbl_dtree_root(t), cask, NULL, &c));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(c, child(cask, "vintage"), &vintage,
	    NULL));
	annotate(c, TS1);
	/* The node alone: its instance, in its annotations. */
	ATF_REQUIRE_EQ(0, cbl_dnode_encode(c, &b));
	got = hex(&b);
	ATF_CHECK_STREQ(H_META "a10a" H_TS1 "a1041907df", got);
	free(got);
	cbl_ybuf_free(&b);
	t = same(t, "a119f0a0" H_META "a10a" H_TS1 "a1041907df");
	check_when(cbl_dnode_first(cbl_dtree_root(t)), TS1);
	cbl_dtree_free(t);
}

/* Figure 4: the list seq, its first entry annotated, by the list's SID. */
ATF_TC_WITHOUT_HEAD(seq);
ATF_TC_BODY(seq, tc)
{
	const struct cbl_ynode *seq = top("mdex", "seq");
	const char *one = "one", *two = "two";
	const void *k1[] = { &one }, *k2[] = { &two };
	cbl_dnode *e;
	cbl_dtree *t;

	ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
	ATF_REQUIRE_EQ(0, cbl_dnode_add_entry(cbl_dtree_root(t), seq, k1, &e));
	annotate(e, TS1);
	ATF_REQUIRE_EQ(0, cbl_dnode_add_entry(cbl_dtree_root(t), seq, k2,
	    NULL));
	t = same(t, "a119f0a182" H_META "a109" H_TS1 "a101636f6e65"
	    "a1016374776f");
	e = cbl_dnode_first(cbl_dtree_root(t));
	check_when(e, TS1);
	ATF_CHECK(cbl_dnode_meta(cbl_dnode_next(e), last_modified()) == NULL);
	cbl_dtree_free(t);
}

/* Figure 5: the leaf foo:flag; a delta below the node's SID. */
ATF_TC_WITHOUT_HEAD(flag);
ATF_TC_BODY(flag, tc)
{
	bool yes = true;
	cbl_dnode *f;
	cbl_dtree *t;

	ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
	ATF_REQUIRE_EQ(0, cbl_dnode_add(cbl_dtree_root(t), top("foo", "flag"),
	    &yes, &f));
	annotate(f, TS1);
	t = same(t, "a119f0b4" H_META "a129" H_TS1 "f5");
	check_when(cbl_dnode_first(cbl_dtree_root(t)), TS1);
	cbl_dtree_free(t);
}

/* Figure 6: the anyxml stuff, [1, null, "three"]. */
ATF_TC_WITHOUT_HEAD(stuff);
ATF_TC_BODY(stuff, tc)
{
	static const uint8_t v[] = { 0x83, 0x01, 0xf6, 0x65, 't', 'h', 'r',
	    'e', 'e' };
	struct cbl_bytes by = { v, sizeof(v) };
	cbl_dnode *s;
	cbl_dtree *t;

	ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
	ATF_REQUIRE_EQ(0, cbl_dnode_add(cbl_dtree_root(t), top("mdex",
	    "stuff"), &by, &s));
	annotate(s, TS1);
	t = same(t, "a119f0a3" H_META "a107" H_TS1 "8301f6657468726565");
	check_when(cbl_dnode_first(cbl_dtree_root(t)), TS1);
	cbl_dtree_free(t);
}

/* Figure 7: the leaf-list folio, two of its entries annotated. */
ATF_TC_WITHOUT_HEAD(folio);
ATF_TC_BODY(folio, tc)
{
	const struct cbl_ynode *folio = top("bibliomod", "folio");
	uint32_t v[] = { 6, 3, 7, 8 };
	const char *when[] = { NULL, TS2, TS1, NULL };
	cbl_dnode *x;
	cbl_dtree *t;
	int i;

	ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
	for (i = 0; i < 4; i++) {
		ATF_REQUIRE_EQ(0, cbl_dnode_add(cbl_dtree_root(t), folio, &v[i],
		    &x));
		if (when[i] != NULL)
			annotate(x, when[i]);
	}
	t = same(t, "a119f0be8406" H_META "a133" H_TS2 "03" H_META "a133"
	    H_TS1 "0708");
	for (i = 0, x = cbl_dnode_first(cbl_dtree_root(t)); x != NULL;
	    x = cbl_dnode_next(x), i++)
		if (when[i] != NULL)
			check_when(x, when[i]);
		else
			ATF_CHECK(cbl_dnode_meta(x, last_modified()) == NULL);
	ATF_CHECK_EQ(4, i);
	cbl_dtree_free(t);
}

/*
 * The structs have no place for an annotation: their decoder passes it
 * over, as a reader may (the draft, section 2), on a value and on a
 * list's entries.
 */
ATF_TC_WITHOUT_HEAD(structs);
ATF_TC_BODY(structs, tc)
{
	const struct cbl_ynode *cask = top("mdex", "cask");
	const struct cbl_ynode *vin = child(cask, "vintage");
	uint8_t bytes[128];
	cbl_yarena *a;
	char why[256];
	void *p;
	size_t n;

	n = unhex(H_META "a10a" H_TS1 "a1041907df", bytes, sizeof(bytes));
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	ATF_REQUIRE((p = cbl_yarena_alloc(a, cask->size)) != NULL);
	ATF_REQUIRE_EQ_MSG(0, cbl_ydecode(cask, bytes, n, p, a,
	    CBL_YD_STRICT, why, sizeof(why)), "%s", why);
	{
		uint16_t got;

		memcpy(&got, (const char *)p + vin->off, sizeof(got));
		ATF_CHECK_EQ(2015, got);
	}
	cbl_yarena_free(a);
}

/*
 * What is not an annotation: a delta to the module's SID (61611), refused
 * strictly, else passed over; an annotated value of other than two
 * items; and the API's own cases.
 */
ATF_TC_WITHOUT_HEAD(refused);
ATF_TC_BODY(refused, tc)
{
	const struct cbl_ynode *flag = top("foo", "flag");
	const char *later = TS2, *const *v;
	const struct cbl_yannot *an;
	const void *value;
	uint8_t bytes[128];
	cbl_dnode *f;
	cbl_dtree *t;
	char why[256];
	size_t n;

	/* -9 from 61620: 61611, the module example-last-modified. */
	n = unhex("a119f0b4" H_META "a128" H_TS1 "f5", bytes, sizeof(bytes));
	ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
	ATF_CHECK_EQ(ENOENT, cbl_dtree_decode(t, bytes, n, CBL_YD_STRICT, why,
	    sizeof(why)));
	ATF_CHECK(strstr(why, "no annotation") != NULL);
	ATF_CHECK(cbl_dnode_first(cbl_dtree_root(t)) == NULL);
	ATF_CHECK_EQ(0, cbl_dtree_decode(t, bytes, n, 0, why, sizeof(why)));
	f = cbl_dnode_first(cbl_dtree_root(t));
	ATF_REQUIRE(f != NULL && cbl_dnode_schema(f) == flag);
	ATF_CHECK(cbl_dnode_meta_next(f, NULL, NULL) == NULL);
	/* A tree that has nodes is not read into. */
	ATF_CHECK_EQ(EEXIST, cbl_dtree_decode(t, bytes, n, 0, why,
	    sizeof(why)));
	cbl_dtree_free(t);
	/* [metadata] alone. */
	n = unhex("a119f0b4d86d81a129" H_TS1, bytes, sizeof(bytes));
	ATF_REQUIRE((t = cbl_dtree_new(&yangh_schema)) != NULL);
	ATF_CHECK_EQ(EINVAL, cbl_dtree_decode(t, bytes, n, 0, why,
	    sizeof(why)));
	ATF_CHECK(cbl_dnode_first(cbl_dtree_root(t)) == NULL);

	/* The API: the root has none; set, replace, take off; by SID. */
	an = last_modified();
	ATF_CHECK_EQ(cbl_yschema_annot(&yangh_schema, 61610), an);
	ATF_CHECK(cbl_yschema_annot(&yangh_schema, 61611) == NULL);
	ATF_CHECK_EQ(EINVAL, cbl_dnode_meta_set(cbl_dtree_root(t), an,
	    &later));
	ATF_REQUIRE_EQ(0, cbl_dnode_add(cbl_dtree_root(t), flag,
	    &(bool){ false }, &f));
	annotate(f, TS1);
	ATF_REQUIRE_EQ(0, cbl_dnode_meta_set(f, an, &later));
	ATF_REQUIRE((v = cbl_dnode_meta(f, an)) != NULL);
	ATF_CHECK_STREQ(TS2, *v);
	ATF_CHECK_EQ(an, cbl_dnode_meta_next(f, NULL, &value));
	ATF_CHECK_STREQ(TS2, *(const char *const *)value);
	ATF_CHECK(cbl_dnode_meta_next(f, an, NULL) == NULL);
	ATF_REQUIRE_EQ(0, cbl_dnode_meta_set(f, an, NULL));
	ATF_CHECK(cbl_dnode_meta(f, an) == NULL);
	cbl_dtree_free(t);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, cask);
	ATF_TP_ADD_TC(tp, seq);
	ATF_TP_ADD_TC(tp, flag);
	ATF_TP_ADD_TC(tp, stuff);
	ATF_TP_ADD_TC(tp, folio);
	ATF_TP_ADD_TC(tp, structs);
	ATF_TP_ADD_TC(tp, refused);
	return (atf_no_error());
}
