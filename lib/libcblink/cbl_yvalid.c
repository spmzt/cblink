/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The static validator (PLAN-SDN-YANG 1.8): what RFC 7950 says of a tree
 * that holds within the tree itself, checked on a struct cblink-gen made
 * of its node, as cbl_ydecode() or a program filled it, by the schema
 * tables.  Each value: its type's ranges, lengths in characters,
 * patterns, enum values, bits, identities derived from the bases, a
 * union's member.  Each node: mandatory leaves and choices, a list's and
 * a leaf-list's counts, a list's keys there and each entry's own, its
 * unique statements, a leaf-list's values each once (config true), one
 * case of each choice, and in an edit no config false node.
 *
 * What needs more than the tree, when and must, a leafref's target and
 * an instance-identifier's, is the evaluator's (cbl_xpath).
 */

#include <errno.h>
#include <pthread.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_pattern.h"
#include "cbl_schema.h"
#include "cbl_dimpl.h"
#include "cbl_yimpl.h"

#define	AT(p, off)	((const void *)((const char *)(p) + (off)))

/* A list's or a leaf-list's member: a count and an array. */
struct yarr {
	size_t		 n;
	const void	*v;
};

struct yv {
	int			 flags;
	struct cbl_yverr	*err;
};

static int
vfail(struct yv *v, const struct cbl_ynode *n, const char *tag,
    const char *apptag, const char *emsg, const char *fmt, ...)
{
	va_list ap;

	if (v->err == NULL)
		return (EINVAL);
	v->err->node = n;
	v->err->tag = tag;
	v->err->apptag = apptag;
	if (emsg != NULL)
		snprintf(v->err->msg, sizeof(v->err->msg), "%s", emsg);
	else {
		va_start(ap, fmt);
		vsnprintf(v->err->msg, sizeof(v->err->msg), fmt, ap);
		va_end(ap);
	}
	return (EINVAL);
}

static int
read_enum(const void *p, uint32_t size)
{

	switch (size) {
	case 1:
		return (*(const int8_t *)p);
	case 2:
		return (*(const int16_t *)p);
	case 8:
		return ((int)*(const int64_t *)p);
	default:
		return (*(const int *)p);
	}
}

/* Whether n is in the case its choices have given, if any. */
static bool
in_case(const struct cbl_ynode *n, const void *p)
{
	const struct cbl_ychoice *c = n->choice;
	uint32_t want = n->ccase;

	for (; c != NULL; want = c->parent_case, c = c->parent)
		if (c->off == CBL_YOFF_NONE ||
		    (uint32_t)read_enum(AT(p, c->off), sizeof(int)) != want + 1)
			return (false);
	return (true);
}

/* Whether choice ch's own place is given: the cases of those above it. */
static bool
choice_applies(const struct cbl_ychoice *ch, const void *p)
{
	uint32_t want = ch->parent_case;

	for (const struct cbl_ychoice *c = ch->parent; c != NULL;
	    want = c->parent_case, c = c->parent)
		if (c->off == CBL_YOFF_NONE ||
		    (uint32_t)read_enum(AT(p, c->off), sizeof(int)) != want + 1)
			return (false);
	return (true);
}

/* Whether child n has a value in struct p, its case aside. */
static bool
has(const struct cbl_ynode *n, const void *p)
{

	if (n->off == CBL_YOFF_NONE)
		return (false);
	switch (n->kind) {
	case CBL_YN_CONTAINER:
		return (*(const void *const *)AT(p, n->off) != NULL);
	case CBL_YN_LIST:
	case CBL_YN_LEAFLIST:
		return (((const struct yarr *)AT(p, n->off))->n > 0);
	case CBL_YN_ANYDATA:
	case CBL_YN_ANYXML:
		return (((const struct cbl_bytes *)AT(p, n->off))->p != NULL);
	case CBL_YN_LEAF:
		break;
	default:
		return (false);
	}
	if (n->hoff != CBL_YOFF_NONE)
		return (*(const bool *)AT(p, n->hoff));
	switch (n->type->kind) {
	case CBL_YT_STRING:
		return (*(const char *const *)AT(p, n->off) != NULL);
	case CBL_YT_BINARY:
	case CBL_YT_BITS:
	case CBL_YT_INSTANCEID:
		return (((const struct cbl_bytes *)AT(p, n->off))->p != NULL);
	case CBL_YT_EMPTY:
		return (*(const bool *)AT(p, n->off));
	default:
		return (true);	/* a key: always there */
	}
}

/*
 * Patterns: each table's ERE compiled once, kept for the process; the
 * tables are static, so their strings' addresses are their keys.
 */
static pthread_mutex_t	pat_mtx = PTHREAD_MUTEX_INITIALIZER;
static struct {
	const char	*ere;
	regex_t		 re;
	bool		 ok;
}			*pats;
static size_t		 npats;

static const regex_t *
pattern(const char *ere)
{
	const regex_t *re = NULL;
	void *nv;
	size_t i;

	pthread_mutex_lock(&pat_mtx);
	for (i = 0; i < npats && pats[i].ere != ere; i++)
		;
	if (i == npats && (nv = reallocarray(pats, npats + 1,
	    sizeof(*pats))) != NULL) {
		pats = nv;
		pats[npats].ere = ere;
		pats[npats].ok = cbl_pattern_compile_ere(ere,
		    &pats[npats].re) == 0;
		npats++;
	}
	if (i < npats && pats[i].ok)
		re = &pats[i].re;
	pthread_mutex_unlock(&pat_mtx);
	return (re);
}

static bool
in_ranges(const struct cbl_yrestrict *r, bool sgn, int64_t i, uint64_t u)
{

	if (r->v == NULL)
		return (true);
	for (uint16_t k = 0; k < r->n; k++)
		if (sgn ? i >= r->v[k].min.i && i <= r->v[k].max.i :
		    u >= r->v[k].min.u && u <= r->v[k].max.u)
			return (true);
	return (false);
}

/* A string's characters: UTF-8's lead bytes; -1 if it is not UTF-8. */
static int64_t
chars(const char *s)
{
	const unsigned char *p = (const unsigned char *)s;
	int64_t n = 0;
	size_t k;

	while (*p != '\0') {
		k = *p < 0x80 ? 1 : (*p & 0xe0) == 0xc0 ? 2 :
		    (*p & 0xf0) == 0xe0 ? 3 : (*p & 0xf8) == 0xf0 ? 4 : 0;
		if (k == 0 || (k == 2 && *p < 0xc2))
			return (-1);
		for (size_t j = 1; j < k; j++)
			if ((p[j] & 0xc0) != 0x80)
				return (-1);
		p += k;
		n++;
	}
	return (n);
}

static int	v_value(struct yv *, const struct cbl_ynode *,
		    const struct cbl_ytype *, const void *);

static int
v_value(struct yv *v, const struct cbl_ynode *n, const struct cbl_ytype *t,
    const void *p)
{
	const struct cbl_yschema *s = n->module->schema;
	const struct cbl_bytes *b;
	int64_t i = 0, len;
	uint64_t u = 0;
	const char *str;
	bool sgn = true;
	int e;

	switch (t->kind) {
	case CBL_YT_INT8:
		i = *(const int8_t *)p;
		break;
	case CBL_YT_INT16:
		i = *(const int16_t *)p;
		break;
	case CBL_YT_INT32:
		i = *(const int32_t *)p;
		break;
	case CBL_YT_INT64:
	case CBL_YT_DECIMAL64:
		i = *(const int64_t *)p;
		break;
	case CBL_YT_UINT8:
		u = *(const uint8_t *)p;
		sgn = false;
		break;
	case CBL_YT_UINT16:
		u = *(const uint16_t *)p;
		sgn = false;
		break;
	case CBL_YT_UINT32:
		u = *(const uint32_t *)p;
		sgn = false;
		break;
	case CBL_YT_UINT64:
		u = *(const uint64_t *)p;
		sgn = false;
		break;
	case CBL_YT_STRING:
		if ((str = *(const char *const *)p) == NULL)
			str = "";
		if ((len = chars(str)) < 0)
			return (vfail(v, n, "invalid-value", NULL, NULL,
			    "%s: not UTF-8", n->name));
		if (!in_ranges(&t->length, false, 0, (uint64_t)len))
			return (vfail(v, n, "invalid-value",
			    t->length.eapptag, t->length.emsg,
			    "%s: %jd characters, not a length allowed",
			    n->name, (intmax_t)len));
		for (uint16_t k = 0; k < t->npatterns; k++) {
			const struct cbl_ypattern *pt = &t->patterns[k];
			const regex_t *re = pattern(pt->ere);

			if (re == NULL)
				return (vfail(v, n, "operation-failed", NULL,
				    NULL, "%s: pattern '%s' does not compile",
				    n->name, pt->xsd));
			if (cbl_pattern_match(re, str) == pt->invert)
				return (vfail(v, n, "invalid-value",
				    pt->eapptag, pt->emsg, "%s: \"%s\" %s "
				    "pattern '%s'", n->name, str, pt->invert ?
				    "matches the inverted" : "does not match",
				    pt->xsd));
		}
		return (0);
	case CBL_YT_BINARY:
		b = p;
		if (!in_ranges(&t->length, false, 0, b->len))
			return (vfail(v, n, "invalid-value",
			    t->length.eapptag, t->length.emsg,
			    "%s: %zu bytes, not a length allowed", n->name,
			    b->len));
		return (0);
	case CBL_YT_BITS:
		b = p;
		for (size_t pos = 0; pos < b->len * 8; pos++) {
			bool known = false;

			if ((((const uint8_t *)b->p)[pos / 8] &
			    (1u << (pos % 8))) == 0)
				continue;
			for (uint32_t k = 0; k < t->nitems && !known; k++)
				known = t->items[k].value == (int64_t)pos;
			if (!known)
				return (vfail(v, n, "invalid-value", NULL,
				    NULL, "%s: no bit at position %zu",
				    n->name, pos));
		}
		return (0);
	case CBL_YT_ENUMERATION:
		e = read_enum(p, t->csize);
		for (uint32_t k = 0; k < t->nitems; k++)
			if (t->items[k].value == e)
				return (0);
		return (vfail(v, n, "invalid-value", NULL, NULL,
		    "%s: no enum of value %d", n->name, e));
	case CBL_YT_IDENTITYREF:
		u = *(const uint64_t *)p;
		if (cbl_yschema_ident(s, u) == NULL)
			return (vfail(v, n, "invalid-value", NULL, NULL,
			    "%s: SID %ju is no identity", n->name,
			    (uintmax_t)u));
		/* RFC 7950 section 9.10.2: derived from every base. */
		for (uint16_t k = 0; k < t->nbases; k++)
			if (!cbl_yderived_from(s, u, t->bases[k], false))
				return (vfail(v, n, "invalid-value", NULL,
				    NULL, "%s: identity %s not derived from "
				    "its base", n->name,
				    cbl_yschema_ident(s, u)->name));
		return (0);
	case CBL_YT_UNION: {
		unsigned which = *(const unsigned *)p;

		if (which >= t->nmembers)
			return (vfail(v, n, "invalid-value", NULL, NULL,
			    "%s: no union member %u", n->name, which));
		return (v_value(v, n, t->members[which], AT(p, t->voff)));
	}
	default:
		/* boolean, empty; instance-identifier: the evaluator's */
		return (0);
	}
	if (!in_ranges(&t->range, sgn, i, u))
		return (vfail(v, n, "invalid-value", t->range.eapptag,
		    t->range.emsg, sgn ? "%s: %jd out of range" :
		    "%s: %ju out of range", n->name, sgn ? (intmax_t)i :
		    (intmax_t)u));
	return (0);
}

bool
cbl_ytype_admits(const struct cbl_yschema *s, const struct cbl_ytype *t,
    const void *p)
{
	struct cbl_ymodule mod;
	struct cbl_ynode n;
	struct yv v = { 0 };

	/* An identity is told by its schema; without one, let it be. */
	if (s == NULL && t->kind == CBL_YT_IDENTITYREF)
		return (true);
	memset(&mod, 0, sizeof(mod));
	memset(&n, 0, sizeof(n));
	mod.schema = s;
	n.module = &mod;
	n.name = "";
	return (v_value(&v, &n, t, p) == 0);
}

/* Two values of type t the same, as RFC 7950 compares them. */
static bool
same(const struct cbl_ytype *t, const void *a, const void *b)
{
	const struct cbl_bytes *x, *y;

	switch (t->kind) {
	case CBL_YT_STRING: {
		const char *s = *(const char *const *)a,
		    *r = *(const char *const *)b;

		return (strcmp(s != NULL ? s : "", r != NULL ? r : "") == 0);
	}
	case CBL_YT_BINARY:
	case CBL_YT_BITS:
	case CBL_YT_INSTANCEID:
		x = a;
		y = b;
		return (x->len == y->len && (x->len == 0 ||
		    memcmp(x->p, y->p, x->len) == 0));
	case CBL_YT_UNION: {
		unsigned i = *(const unsigned *)a, j = *(const unsigned *)b;

		return (i == j && i < t->nmembers && same(t->members[i],
		    AT(a, t->voff), AT(b, t->voff)));
	}
	case CBL_YT_ENUMERATION:
		return (read_enum(a, t->csize) == read_enum(b, t->csize));
	default:
		return (memcmp(a, b, t->csize) == 0);
	}
}

/* A unique leaf's value in an entry, or NULL: not there. */
static const void *
unique_leaf(const struct cbl_ynode *const *path, const void *entry)
{
	const void *p = entry;

	for (; path[1] != NULL; path++) {
		/* A container down the path: its struct, if there. */
		if ((p = *(const void *const *)AT(p, (*path)->off)) == NULL)
			return (NULL);
	}
	if (!has(*path, p) || !in_case(*path, p))
		return (NULL);
	return (AT(p, (*path)->off));
}

static int	v_mounted(struct yv *, const struct cbl_ynode *, const void *,
		    int);
static int	v_struct(struct yv *, const struct cbl_ynode *, const void *,
		    int);

/* A list: its count, each entry, keys there and each once, unique. */
static int
v_list(struct yv *v, const struct cbl_ynode *n, const struct yarr *a,
    int depth)
{
	int error;

	for (size_t i = 0; i < a->n; i++) {
		const void *e = AT(a->v, i * n->size);

		for (uint16_t k = 0; k < n->nkeys; k++) {
			const struct cbl_ynode *kn = n->child[n->keys[k]];

			if (kn->type->kind == CBL_YT_STRING &&
			    *(const char *const *)AT(e, kn->off) == NULL)
				return (vfail(v, kn, "missing-element", NULL,
				    NULL, "%s: an entry without its key %s",
				    n->name, kn->name));
		}
		if ((error = v_struct(v, n, e, depth + 1)) != 0)
			return (error);
		/* Its keys, no other entry's. */
		for (size_t j = 0; j < i && n->nkeys > 0; j++) {
			const void *f = AT(a->v, j * n->size);
			uint16_t k;

			for (k = 0; k < n->nkeys; k++) {
				const struct cbl_ynode *kn =
				    n->child[n->keys[k]];

				if (!same(kn->type, AT(e, kn->off),
				    AT(f, kn->off)))
					break;
			}
			if (k == n->nkeys)
				return (vfail(v, n, "data-exists", NULL, NULL,
				    "%s: two entries of one key (%s)",
				    n->name, n->child[n->keys[0]]->name));
		}
		/* RFC 7950 section 7.8.3: where all the leaves are. */
		for (uint16_t u = 0; u < n->nunique; u++) {
			const struct cbl_yunique *un = &n->unique[u];

			for (size_t j = 0; j < i; j++) {
				const void *f = AT(a->v, j * n->size);
				uint16_t k;

				for (k = 0; k < un->n; k++) {
					const struct cbl_ynode *const *path =
					    un->leaf[k];
					const struct cbl_ynode *leaf;
					const void *x, *y;

					for (leaf = *path; path[1] != NULL;
					    path++)
						leaf = path[1];
					x = unique_leaf(un->leaf[k], e);
					y = unique_leaf(un->leaf[k], f);
					if (x == NULL || y == NULL ||
					    !same(leaf->type, x, y))
						break;
				}
				if (k == un->n)
					return (vfail(v, n, "operation-failed",
					    "data-not-unique", NULL, "%s: two "
					    "entries alike in what is unique",
					    n->name));
			}
		}
	}
	return (0);
}

/* A leaf-list: each value, and each once when it is configuration. */
static int
v_leaflist(struct yv *v, const struct cbl_ynode *n, const struct yarr *a)
{
	const struct cbl_ytype *t = n->type;
	int error;

	for (size_t i = 0; i < a->n; i++) {
		const void *x = AT(a->v, i * t->csize);

		if ((error = v_value(v, n, t, x)) != 0)
			return (error);
		for (size_t j = 0; j < i && (n->flags & CBL_YNF_CONFIG); j++)
			if (same(t, x, AT(a->v, j * t->csize)))
				return (vfail(v, n, "data-exists", NULL, NULL,
				    "%s: a value twice", n->name));
	}
	return (0);
}

/* A count against min-elements and max-elements. */
static int
v_count(struct yv *v, const struct cbl_ynode *n, size_t count)
{

	if (count < n->min)
		return (vfail(v, n, "operation-failed", "too-few-elements",
		    NULL, "%s: %zu, fewer than %u", n->name, count, n->min));
	if (n->max != 0 && count > n->max)
		return (vfail(v, n, "operation-failed", "too-many-elements",
		    NULL, "%s: %zu, more than %u", n->name, count, n->max));
	return (0);
}

/* A mandatory node anywhere below n, not under a presence container;
 * with edit, configuration alone (state is no edit's). */
static const struct cbl_ynode *
mandatory_below(const struct cbl_ynode *n, int depth, bool edit)
{
	const struct cbl_ynode *m;

	if (depth > 64)
		return (NULL);
	for (uint32_t i = 0; i < n->nchild; i++) {
		const struct cbl_ynode *c = n->child[i];

		if (edit && (c->flags & CBL_YNF_CONFIG) == 0)
			continue;
		/* A when's node is not there unless it holds, which
		 * nothing absent makes it (RFC 7950 section 7.21.5). */
		if (c->nwhen > 0)
			continue;
		/* A case's nodes only in the case given, which none is
		 * here: a mandatory choice says so for them (7.9.4). */
		if (c->choice != NULL) {
			const struct cbl_ychoice *top = c->choice;

			while (top->parent != NULL)
				top = top->parent;
			if (top->mandatory && top->nwhen == 0)
				return (c);
			continue;
		}
		if (c->kind == CBL_YN_LEAF && (c->flags & CBL_YNF_MANDATORY))
			return (c);
		if ((c->kind == CBL_YN_LIST || c->kind == CBL_YN_LEAFLIST) &&
		    c->min > 0)
			return (c);
		if (c->kind == CBL_YN_CONTAINER &&
		    (c->flags & CBL_YNF_PRESENCE) == 0 &&
		    (m = mandatory_below(c, depth + 1, edit)) != NULL)
			return (m);
	}
	return (NULL);
}

static int
v_struct(struct yv *v, const struct cbl_ynode *n, const void *p, int depth)
{
	const struct cbl_ynode *m;
	int error;

	if (depth > 64)
		return (vfail(v, n, "operation-failed", NULL, NULL,
		    "%s: nested too deep", n->name));
	for (uint32_t i = 0; i < n->nchild; i++) {
		const struct cbl_ynode *c = n->child[i];
		const struct cbl_ychoice *ch = c->choice;
		bool there = has(c, p);

		if (c->off == CBL_YOFF_NONE)
			continue;
		/*
		 * A mandatory choice none of whose cases is given, where it
		 * applies: a choice in a case, only in the case given.
		 */
		if (ch != NULL && ch->mandatory && ch->off != CBL_YOFF_NONE &&
		    read_enum(AT(p, ch->off), sizeof(int)) == 0 &&
		    choice_applies(ch, p))
			return (vfail(v, c, "data-missing", "missing-choice",
			    NULL, "%s: no case of choice %s", n->name,
			    ch->name));
		/*
		 * A node of a case not given is not there; one that says it is
		 * (a key, always there, is in no case) is a second case.
		 */
		if (ch != NULL && !in_case(c, p)) {
			if (there)
				return (vfail(v, c, "bad-element", NULL, NULL,
				    "%s: in a case of %s not the one given",
				    c->name, ch->name));
			continue;
		}
		if (there && (v->flags & CBL_YV_EDIT) &&
		    (c->flags & CBL_YNF_CONFIG) == 0 &&
		    (c->kind == CBL_YN_LEAF || c->kind == CBL_YN_LEAFLIST ||
		    c->kind == CBL_YN_LIST || c->kind == CBL_YN_CONTAINER))
			return (vfail(v, c, "invalid-value", NULL, NULL,
			    "%s: state, not configuration: not edited",
			    c->name));
		/* State's rules are the operational datastore's. */
		if ((v->flags & CBL_YV_EDIT) && (c->flags & CBL_YNF_CONFIG) ==
		    0 && c->kind != CBL_YN_RPC && c->kind != CBL_YN_ACTION &&
		    c->kind != CBL_YN_NOTIF)
			continue;
		switch (c->kind) {
		case CBL_YN_LEAF:
			if (!there) {
				/* Under a when: the tree's to judge
				 * (cbl_dnode_check_conds()). */
				if ((c->flags & CBL_YNF_MANDATORY) &&
				    c->nwhen == 0)
					return (vfail(v, c, "missing-element",
					    NULL, NULL, "%s: mandatory, "
					    "missing", c->name));
				break;
			}
			if ((error = v_value(v, c, c->type,
			    AT(p, c->off))) != 0)
				return (error);
			break;
		case CBL_YN_LEAFLIST:
			if (c->nwhen > 0 && ((const struct yarr *)AT(p,
			    c->off))->n == 0)
				break;
			if ((error = v_count(v, c,
			    ((const struct yarr *)AT(p, c->off))->n)) != 0 ||
			    (error = v_leaflist(v, c, AT(p, c->off))) != 0)
				return (error);
			break;
		case CBL_YN_LIST:
			if (c->nwhen > 0 && ((const struct yarr *)AT(p,
			    c->off))->n == 0)
				break;
			if ((error = v_count(v, c,
			    ((const struct yarr *)AT(p, c->off))->n)) != 0 ||
			    (error = v_list(v, c, AT(p, c->off),
			    depth)) != 0)
				return (error);
			break;
		case CBL_YN_CONTAINER:
			if (there) {
				if ((error = v_struct(v, c,
				    *(const void *const *)AT(p, c->off),
				    depth + 1)) != 0)
					return (error);
			} else if ((c->flags & CBL_YNF_PRESENCE) == 0 &&
			    c->nwhen == 0 && (m = mandatory_below(c, 0,
			    (v->flags & CBL_YV_EDIT) != 0)) != NULL)
				/* It is there in effect: what it needs too. */
				return (vfail(v, m, "missing-element", NULL,
				    NULL, "%s: mandatory, missing", m->name));
			break;
		default:
			break;
		}
	}
	return (n->flags & CBL_YNF_MOUNT ? v_mounted(v, n, p, depth) : 0);
}

/* What mount point n has mounted (RFC 8528): each module's top-level
 * nodes there, as a module's data is validated. */
static int
v_mounted(struct yv *v, const struct cbl_ynode *n, const void *p,
    int depth)
{
	const struct cbl_ymounts *m;
	const struct cbl_ynode **kid;
	struct cbl_ynode top;
	int error = 0;

	m = (const struct cbl_ymounts *)AT(p, n->moff);
	for (size_t i = 0; error == 0 && i < m->n; i++) {
		const struct cbl_ymodule *mod = m->v[i].module;
		uint32_t k = 0;

		if (m->v[i].data == NULL)
			continue;
		if ((kid = calloc(mod->ntop + 1, sizeof(*kid))) == NULL)
			return (ENOMEM);
		for (uint32_t j = 0; j < mod->ntop; j++)
			if (has(mod->top[j], m->v[i].data))
				kid[k++] = mod->top[j];
		memset(&top, 0, sizeof(top));
		top.name = mod->name;
		top.module = mod;
		top.nchild = k;
		top.child = kid;
		top.size = mod->size;
		error = v_struct(v, &top, m->v[i].data, depth + 1);
		free(kid);
	}
	return (error);
}

int
cbl_yvalidate(const struct cbl_ynode *n, const void *p, int flags,
    struct cbl_yverr *err)
{
	struct yv v = { .flags = flags, .err = err };

	if (err != NULL)
		memset(err, 0, sizeof(*err));
	if (n == NULL || p == NULL || n->size == 0)
		return (EINVAL);
	return (v_struct(&v, n, p, 0));
}

int
cbl_yvalidate_member(const struct cbl_ynode *n, const void *parent,
    int flags, struct cbl_yverr *err)
{
	struct cbl_ynode top = { 0 };
	const struct cbl_ynode *kid[1] = { n };

	if (n == NULL || parent == NULL)
		return (EINVAL);
	/* n as the only child of its module's data. */
	top.name = n->module->name;
	top.module = n->module;
	top.nchild = 1;
	top.child = kid;
	top.size = n->module->size;
	return (cbl_yvalidate(&top, parent, flags, err));
}

/*
 * Defaults (RFC 7950 sections 7.6.1, 7.7.2 and 7.9.3): what a struct has
 * not set, set to the default the module gives, from its canonical form
 * as the tables keep it.
 */

#define	WAT(p, off)	((void *)((char *)(p) + (off)))

static void
write_enum(void *p, uint32_t size, int v)
{

	switch (size) {
	case 1:
		*(int8_t *)p = (int8_t)v;
		break;
	case 2:
		*(int16_t *)p = (int16_t)v;
		break;
	case 8:
		*(int64_t *)p = v;
		break;
	default:
		*(int *)p = v;
		break;
	}
}

/* A decimal64's canonical text, scaled by its fraction digits. */
static int
parse_decimal(const char *s, uint8_t fdigits, int64_t *vp)
{
	bool neg = *s == '-';
	uint64_t v = 0;
	unsigned fd = 0;
	bool point = false;

	if (neg)
		s++;
	if (*s == '\0')
		return (EINVAL);
	for (; *s != '\0'; s++) {
		if (*s == '.' && !point) {
			point = true;
			continue;
		}
		if (*s < '0' || *s > '9' || (point && fd == fdigits) ||
		    v > (UINT64_MAX - 9) / 10)
			return (EINVAL);
		v = v * 10 + (uint64_t)(*s - '0');
		if (point)
			fd++;
	}
	for (; fd < fdigits; fd++) {
		if (v > UINT64_MAX / 10)
			return (EINVAL);
		v *= 10;
	}
	if (v > (uint64_t)INT64_MAX + (neg ? 1 : 0))
		return (EINVAL);
	*vp = neg ? (int64_t)(0 - v) : (int64_t)v;
	return (0);
}

/* Base64 (RFC 4648), as a binary's canonical form is. */
static int
base64(const char *s, cbl_yarena *a, struct cbl_bytes *b)
{
	static const char al[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t len = strlen(s), n = 0;
	uint32_t acc = 0;
	int bits = 0;
	uint8_t *out;

	if ((out = cbl_yarena_alloc(a, len / 4 * 3 + 3)) == NULL)
		return (ENOMEM);
	for (; *s != '\0' && *s != '='; s++) {
		const char *q = strchr(al, *s);

		if (q == NULL)
			return (EINVAL);
		acc = acc << 6 | (uint32_t)(q - al);
		if ((bits += 6) >= 8) {
			bits -= 8;
			out[n++] = (uint8_t)(acc >> bits);
		}
	}
	b->p = out;
	b->len = n;
	return (0);
}

static int	parse_value(const struct cbl_ynode *, const struct cbl_ytype *,
		    const char *, void *, cbl_yarena *);

int
cbl_yvalue_parse(const struct cbl_ynode *n, const struct cbl_ytype *t,
    const char *s, void *out, cbl_yarena *a)
{

	if (n == NULL || t == NULL || s == NULL || out == NULL)
		return (EINVAL);
	return (parse_value(n, t, s, out, a));
}

static int
parse_value(const struct cbl_ynode *n, const struct cbl_ytype *t,
    const char *s, void *out, cbl_yarena *a)
{
	const struct cbl_yschema *sc = n->module->schema;
	char *end;
	int64_t i;
	uint64_t u;

	switch (t->kind) {
	case CBL_YT_INT8:
	case CBL_YT_INT16:
	case CBL_YT_INT32:
	case CBL_YT_INT64:
		errno = 0;
		i = strtoll(s, &end, 10);
		if (errno != 0 || *end != '\0')
			return (EINVAL);
		if (t->kind == CBL_YT_INT8)
			*(int8_t *)out = (int8_t)i;
		else if (t->kind == CBL_YT_INT16)
			*(int16_t *)out = (int16_t)i;
		else if (t->kind == CBL_YT_INT32)
			*(int32_t *)out = (int32_t)i;
		else
			*(int64_t *)out = i;
		return (0);
	case CBL_YT_UINT8:
	case CBL_YT_UINT16:
	case CBL_YT_UINT32:
	case CBL_YT_UINT64:
		errno = 0;
		u = strtoull(s, &end, 10);
		if (errno != 0 || *end != '\0' || *s == '-')
			return (EINVAL);
		if (t->kind == CBL_YT_UINT8)
			*(uint8_t *)out = (uint8_t)u;
		else if (t->kind == CBL_YT_UINT16)
			*(uint16_t *)out = (uint16_t)u;
		else if (t->kind == CBL_YT_UINT32)
			*(uint32_t *)out = (uint32_t)u;
		else
			*(uint64_t *)out = u;
		return (0);
	case CBL_YT_DECIMAL64:
		return (parse_decimal(s, t->fdigits, out));
	case CBL_YT_BOOLEAN:
		if (strcmp(s, "true") != 0 && strcmp(s, "false") != 0)
			return (EINVAL);
		*(bool *)out = strcmp(s, "true") == 0;
		return (0);
	case CBL_YT_STRING:
		/* The tables' own string: it lasts as they do. */
		*(const char **)out = s;
		return (0);
	case CBL_YT_ENUMERATION:
		for (uint32_t k = 0; k < t->nitems; k++)
			if (strcmp(t->items[k].name, s) == 0) {
				write_enum(out, t->csize,
				    (int)t->items[k].value);
				return (0);
			}
		return (EINVAL);
	case CBL_YT_BITS: {
		struct cbl_bytes *b = out;
		int64_t max = -1;
		uint8_t *bytes;
		size_t len;

		for (uint32_t k = 0; k < t->nitems; k++)
			if (t->items[k].value > max)
				max = t->items[k].value;
		len = max < 0 ? 0 : (size_t)(max / 8 + 1);
		if ((bytes = cbl_yarena_alloc(a, len)) == NULL)
			return (ENOMEM);
		while (*s != '\0') {
			size_t w = strcspn(s, " ");
			uint32_t k;

			for (k = 0; k < t->nitems; k++)
				if (strlen(t->items[k].name) == w &&
				    strncmp(t->items[k].name, s, w) == 0)
					break;
			if (k == t->nitems)
				return (EINVAL);
			bytes[t->items[k].value / 8] |=
			    (uint8_t)(1u << (t->items[k].value % 8));
			s += w;
			s += strspn(s, " ");
		}
		/* No zero bytes at the end, as the codec sends them. */
		while (len > 0 && bytes[len - 1] == 0)
			len--;
		b->p = bytes;
		b->len = len;
		return (0);
	}
	case CBL_YT_BINARY:
		return (base64(s, a, out));
	case CBL_YT_IDENTITYREF: {
		const char *colon = strchr(s, ':'), *name;
		size_t ml = colon != NULL ? (size_t)(colon - s) : 0;

		name = colon != NULL ? colon + 1 : s;
		for (uint32_t k = 0; k < sc->nident; k++) {
			const struct cbl_yident *id = &sc->ident[k];

			if (strcmp(id->name, name) != 0 || (colon != NULL &&
			    (strlen(id->module->name) != ml ||
			    strncmp(id->module->name, s, ml) != 0)))
				continue;
			*(uint64_t *)out = id->sid;
			return (0);
		}
		return (EINVAL);
	}
	case CBL_YT_UNION: {
		struct yv v = { 0 };

		/* The first member it is a value of (RFC 7950 9.12). */
		for (unsigned k = 0; k < t->nmembers; k++) {
			void *m = WAT(out, t->voff);

			memset(m, 0, t->csize - t->voff);
			if (parse_value(n, t->members[k], s, m, a) == 0 &&
			    v_value(&v, n, t->members[k], m) == 0) {
				*(unsigned *)out = k;
				return (0);
			}
		}
		return (EINVAL);
	}
	default:
		/* empty has none; an instance-identifier's: not yet. */
		return (EOPNOTSUPP);
	}
}

int
cbl_ydefault_parse(const struct cbl_ynode *n, uint16_t k, void *out,
    cbl_yarena *a)
{

	if (n == NULL || n->type == NULL || k >= n->ndflt)
		return (EINVAL);
	return (parse_value(n, n->type, n->dflt[k], out, a));
}

static int	d_struct(const struct cbl_ynode *, void *, cbl_yarena *, int);

static int
d_struct(const struct cbl_ynode *n, void *p, cbl_yarena *a, int depth)
{
	int error;

	if (depth > 64)
		return (ELOOP);
	/* A choice with no case given: its default case, where it applies. */
	for (uint32_t i = 0; i < n->nchild; i++) {
		const struct cbl_ychoice *ch = n->child[i]->choice;

		if (ch != NULL && ch->dflt >= 0 && ch->off != CBL_YOFF_NONE &&
		    read_enum(AT(p, ch->off), sizeof(int)) == 0 &&
		    choice_applies(ch, p))
			write_enum(WAT(p, ch->off), sizeof(int), ch->dflt + 1);
	}
	for (uint32_t i = 0; i < n->nchild; i++) {
		const struct cbl_ynode *c = n->child[i];
		struct yarr *arr;

		if (c->off == CBL_YOFF_NONE || (c->choice != NULL &&
		    !in_case(c, p)))
			continue;
		switch (c->kind) {
		case CBL_YN_LEAF:
			if (c->ndflt == 0 || has(c, p))
				break;
			if ((error = parse_value(c, c->type, c->dflt[0],
			    WAT(p, c->off), a)) != 0)
				return (error == EOPNOTSUPP ? 0 : error);
			if (c->hoff != CBL_YOFF_NONE)
				*(bool *)WAT(p, c->hoff) = true;
			break;
		case CBL_YN_LEAFLIST: {
			uint8_t *v;

			arr = WAT(p, c->off);
			if (c->ndflt == 0 || arr->n > 0)
				break;
			if ((v = cbl_yarena_alloc(a, c->ndflt *
			    c->type->csize)) == NULL)
				return (ENOMEM);
			for (uint16_t k = 0; k < c->ndflt; k++)
				if ((error = parse_value(c, c->type,
				    c->dflt[k], v + k * c->type->csize,
				    a)) != 0)
					return (error == EOPNOTSUPP ? 0 :
					    error);
			arr->n = c->ndflt;
			arr->v = v;
			break;
		}
		case CBL_YN_CONTAINER: {
			void *q = *(void *const *)AT(p, c->off);

			if (q != NULL && (error = d_struct(c, q, a,
			    depth + 1)) != 0)
				return (error);
			break;
		}
		case CBL_YN_LIST:
			/* Writable, as cbl_ydefaults() asks of the tree. */
			arr = WAT(p, c->off);
			for (size_t k = 0; k < arr->n; k++)
				if ((error = d_struct(c, WAT((void *)(uintptr_t)
				    arr->v, k * c->size), a, depth + 1)) != 0)
					return (error);
			break;
		default:
			break;
		}
	}
	return (0);
}

int
cbl_ydefaults(const struct cbl_ynode *n, void *p, cbl_yarena *a)
{

	if (n == NULL || p == NULL || a == NULL || n->size == 0)
		return (EINVAL);
	return (d_struct(n, p, a, 0));
}
