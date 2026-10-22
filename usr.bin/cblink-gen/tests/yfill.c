/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A struct of any node filled by the schema tables alone, and its round
 * trip through YANG-CBOR: encoded, decoded (strictly), encoded again,
 * the same bytes.  The encoder reads every field the tables give, so
 * the same bytes say the decoder put back each.  For yang_h_test and
 * for a whole corpus (tools/yangwalk/tablecheck.sh).
 *
 * A pass fills every optional leaf, or only what must be (keys, and the
 * containers and lists that hold them); and picks, by its number, a
 * case of each choice and a member of each union.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_schema.h>

#include "yfill.h"

#define	AT(p, off)	((void *)((char *)(p) + (off)))

struct yfill {
	int		 pass;
	bool		 all;
	unsigned	 n;		/* a counter, for values that differ */
	void		**ptrs;
	size_t		 nptrs;
};

static void *
falloc(struct yfill *f, size_t len)
{
	void *p;

	if ((p = calloc(1, len == 0 ? 1 : len)) == NULL)
		abort();
	if ((f->ptrs = reallocarray(f->ptrs, f->nptrs + 1,
	    sizeof(*f->ptrs))) == NULL)
		abort();
	f->ptrs[f->nptrs++] = p;
	return (p);
}

static void
put_enum(void *p, uint32_t size, int v)
{

	if (size == 1)
		*(int8_t *)p = (int8_t)v;
	else if (size == 2)
		*(int16_t *)p = (int16_t)v;
	else if (size == 8)
		*(int64_t *)p = v;
	else
		*(int *)p = v;
}

/* A value of type t at v. */
static void
fill_value(struct yfill *f, const struct cbl_ytype *t, void *v)
{
	struct cbl_bytes *b;
	char *s;
	uint8_t *d;
	unsigned k = f->n++;

	switch (t->kind) {
	case CBL_YT_INT8:
		*(int8_t *)v = (int8_t)(k % 2 ? -7 : 7);
		break;
	case CBL_YT_INT16:
		*(int16_t *)v = (int16_t)(k % 2 ? -700 : 700);
		break;
	case CBL_YT_INT32:
		*(int32_t *)v = k % 2 ? -70000 : 70000;
		break;
	case CBL_YT_INT64:
	case CBL_YT_DECIMAL64:
		*(int64_t *)v = k % 2 ? -7000000000LL : 7000000000LL;
		break;
	case CBL_YT_UINT8:
		*(uint8_t *)v = (uint8_t)(200 + k % 50);
		break;
	case CBL_YT_UINT16:
		*(uint16_t *)v = (uint16_t)(60000 + k % 50);
		break;
	case CBL_YT_UINT32:
		*(uint32_t *)v = 4000000000U + k;
		break;
	case CBL_YT_UINT64:
	case CBL_YT_IDENTITYREF:
		*(uint64_t *)v = UINT64_C(1099511627776) + k;
		break;
	case CBL_YT_BOOLEAN:
		*(bool *)v = k % 2 == 0;
		break;
	case CBL_YT_EMPTY:
		*(bool *)v = true;
		break;
	case CBL_YT_STRING:
		s = falloc(f, 32);
		snprintf(s, 32, "value-%u", k);
		*(const char **)v = s;
		break;
	case CBL_YT_BINARY:
	case CBL_YT_BITS:
		d = falloc(f, 3);
		d[0] = (uint8_t)k;
		d[1] = 0x05;
		d[2] = 0x80;
		b = v;
		b->p = d;
		b->len = t->kind == CBL_YT_BITS ? 1 + k % 3 : 3;
		break;
	case CBL_YT_INSTANCEID:
		/* A SID: 1700, as CBOR. */
		d = falloc(f, 3);
		d[0] = 0x19;
		d[1] = 0x06;
		d[2] = 0xa4;
		b = v;
		b->p = d;
		b->len = 3;
		break;
	case CBL_YT_ENUMERATION:
		/* By the pass and the counter: a leaf-list's differ. */
		if (t->nitems > 0)
			put_enum(v, t->csize, (int)t->items[((unsigned)f->pass +
			    k) % t->nitems].value);
		break;
	case CBL_YT_UNION:
		if (t->nmembers == 0)
			break;
		*(unsigned *)v = (unsigned)f->pass % t->nmembers;
		fill_value(f, t->members[*(unsigned *)v], AT(v, t->voff));
		break;
	}
}

/* Whether a child in a choice is in the case this pass picks. */
static bool
picked(const struct yfill *f, const struct cbl_ynode *c)
{
	const struct cbl_ychoice *ch = c->choice;
	uint32_t want = c->ccase;

	for (; ch != NULL; want = ch->parent_case, ch = ch->parent)
		if (ch->ncases > 0 && want != (unsigned)f->pass % ch->ncases)
			return (false);
	return (true);
}

static void
set_cases(const struct cbl_ynode *c, void *p)
{
	const struct cbl_ychoice *ch = c->choice;
	uint32_t want = c->ccase;

	for (; ch != NULL; want = ch->parent_case, ch = ch->parent)
		if (ch->off != CBL_YOFF_NONE)
			put_enum(AT(p, ch->off), sizeof(int), (int)want + 1);
}

static void	fill_struct(struct yfill *, const struct cbl_ynode *, void *,
		    int);

/* How many entries a list or a leaf-list gets at this depth. */
static size_t
entries(int depth)
{

	return (depth < 3 ? 2 : 1);
}

static void
fill_child(struct yfill *f, const struct cbl_ynode *c, void *p, int depth)
{
	struct { size_t n; void *v; } *a;
	struct cbl_bytes *b;
	uint8_t *d;
	void *q;
	size_t n;

	switch (c->kind) {
	case CBL_YN_CONTAINER:
		q = falloc(f, c->size);
		fill_struct(f, c, q, depth + 1);
		*(void **)AT(p, c->off) = q;
		break;
	case CBL_YN_LIST:
		n = entries(depth);
		q = falloc(f, n * c->size);
		for (size_t i = 0; i < n; i++)
			fill_struct(f, c, AT(q, i * c->size), depth + 1);
		a = AT(p, c->off);
		a->n = n;
		a->v = q;
		break;
	case CBL_YN_LEAFLIST:
		if (!f->all)
			return;
		n = entries(depth);
		/* Each value once, as a configuration leaf-list has it. */
		if (c->type->kind == CBL_YT_ENUMERATION && c->type->nitems < n)
			n = c->type->nitems;
		q = falloc(f, n * c->type->csize);
		for (size_t i = 0; i < n; i++)
			fill_value(f, c->type, AT(q, i * c->type->csize));
		a = AT(p, c->off);
		a->n = n;
		a->v = q;
		break;
	case CBL_YN_LEAF:
		if (!f->all && !(c->flags & CBL_YNF_KEY))
			return;
		fill_value(f, c->type, AT(p, c->off));
		if (c->hoff != CBL_YOFF_NONE)
			*(bool *)AT(p, c->hoff) = true;
		break;
	case CBL_YN_ANYDATA:
	case CBL_YN_ANYXML:
		if (!f->all)
			return;
		/* {1: "x"}, as CBOR. */
		d = falloc(f, 4);
		d[0] = 0xa1;
		d[1] = 0x01;
		d[2] = 0x61;
		d[3] = 'x';
		b = AT(p, c->off);
		b->p = d;
		b->len = 4;
		break;
	default:
		return;
	}
	set_cases(c, p);
}

static void
fill_struct(struct yfill *f, const struct cbl_ynode *n, void *p, int depth)
{

	/* Deep enough: the shapes are all met higher up. */
	if (depth > 24)
		return;
	for (uint32_t i = 0; i < n->nchild; i++) {
		const struct cbl_ynode *c = n->child[i];

		if (c->off == CBL_YOFF_NONE || !picked(f, c))
			continue;
		fill_child(f, c, p, depth);
	}
}

int
yencoded(const struct cbl_ynode *n, int pass, bool all, struct cbl_ybuf *b)
{
	struct yfill f = { .pass = pass, .all = all };
	void *p;
	int error;

	if (n->size == 0)
		return (EINVAL);
	p = falloc(&f, n->size);
	fill_struct(&f, n, p, 0);
	error = cbl_yencode(n, p, b);
	for (size_t i = 0; i < f.nptrs; i++)
		free(f.ptrs[i]);
	free(f.ptrs);
	return (error);
}

int
yround(const struct cbl_ynode *n, int pass, bool all, char *why,
    size_t whylen)
{
	struct yfill f = { .pass = pass, .all = all };
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	cbl_yarena *a;
	void *p, *q;
	int error;

	if (n->size == 0) {
		snprintf(why, whylen, "%s: no struct", n->name);
		return (-1);
	}
	p = falloc(&f, n->size);
	fill_struct(&f, n, p, 0);
	if ((error = cbl_yencode(n, p, &b1)) != 0) {
		snprintf(why, whylen, "%s: encode: %s", n->name,
		    strerror(error));
		goto out;
	}
	if ((a = cbl_yarena_new()) == NULL)
		abort();
	q = falloc(&f, n->size);
	if ((error = cbl_ydecode(n, b1.p, b1.len, q, a, CBL_YD_STRICT, why,
	    whylen)) != 0) {
		cbl_yarena_free(a);
		goto out;
	}
	if ((error = cbl_yencode(n, q, &b2)) != 0) {
		snprintf(why, whylen, "%s: encode again: %s", n->name,
		    strerror(error));
		cbl_yarena_free(a);
		goto out;
	}
	cbl_yarena_free(a);
	if (b1.len != b2.len || memcmp(b1.p, b2.p, b1.len) != 0) {
		snprintf(why, whylen, "%s: %zu bytes, %zu decoded and encoded "
		    "again, not the same", n->name, b1.len, b2.len);
		error = -1;
	}
out:
	cbl_ybuf_free(&b1);
	cbl_ybuf_free(&b2);
	for (size_t i = 0; i < f.nptrs; i++)
		free(f.ptrs[i]);
	free(f.ptrs);
	return (error);
}

size_t
yround_all(const struct cbl_yschema *s, size_t *nencoded, char *why,
    size_t whylen)
{
	size_t bad = 0, done = 0;

	for (uint32_t i = 0; i < s->nnode; i++) {
		const struct cbl_ynode *n = s->node[i];

		if (n->size == 0)
			continue;
		for (int pass = 0; pass < 3; pass++)
			for (int all = 0; all < 2; all++) {
				if (yround(n, pass, all != 0, why, whylen) !=
				    0) {
					fprintf(stderr, "%s\n", why);
					bad++;
				}
				done++;
			}
	}
	if (nencoded != NULL)
		*nencoded = done;
	return (bad);
}
