/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The schema tables of YANG modules (-m schema, PLAN-SDN-YANG 1.6.2):
 * base_schema.c, the cbl_schema.h structures the library decodes,
 * encodes and validates by, for the modules gen_yang_h() makes structs
 * of.  Every node, choices and cases passed through, has its children
 * sorted by SID; every node and identityref base must have a SID (their
 * modules' .sid files, -s).  Types are shared by the nodes that have
 * the same one, expressions by the statements that have the same text.
 * What each module's tables come to is said on standard output and at
 * the top of the file.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_pattern.h"
#include "cbl_schema.h"
#include "gen.h"
#include "schema.h"

/* A pointer's number, by open addressing. */
struct pmap {
	const void	**k;
	size_t		 *v;
	size_t		  cap, n;
};

struct topn {
	size_t		 n;		/* its number */
	uint64_t	 sid;
};

struct ys {
	struct diags	*d;
	struct buf	 types;		/* type definitions, members first */
	struct buf	 body;		/* the rest */
	struct buf	 codec;		/* each struct's encoder and decoder */
	struct pmap	 nodes;		/* snode -> its number */
	struct pmap	 structs;	/* sx:structure sext -> its number */
	struct pmap	 choices;	/* choice snode -> its number */
	struct pmap	 mods;		/* smodule -> its number */
	struct pmap	 bases;		/* identityref bases met, a set */
	const struct sident **basev;
	size_t		 nbase;
	struct topn	*all;		/* every node: number and SID */
	size_t		 nall;
	size_t		 ndense, nmapped, nsearched;	/* how children are found */
	bool		*mref;		/* a node is of it: it is defined */
	size_t		 nnodes, nchoices, ntypes, nmods;
	char		**tkeys;	/* each type's key, by number */
	char		**xp;		/* the expressions, by number */
	size_t		 nxp;
	const struct smodule *m;	/* the module whose tables these are */
	size_t		 mnodes, mtypes, mbytes;	/* its counts */
	char		**codecs;	/* the structs whose codec is written */
	size_t		 ncodecs;
};

static void	top_add(struct topn **, size_t *, size_t, uint64_t);
static void	map_emit(struct ys *, size_t, const struct snode **, size_t,
		    struct buf *);
static bool	member_of(struct buf *, const struct snode *);
static int	top_cmp(const void *, const void *);

static size_t
phash(const void *p, size_t cap)
{
	uintptr_t x = (uintptr_t)p;

	x ^= x >> 17;
	x *= 0x9e3779b97f4a7c15ULL;
	return ((size_t)(x >> 7) & (cap - 1));
}

static bool
pmap_get(const struct pmap *m, const void *p, size_t *vp)
{
	size_t i;

	if (m->cap == 0)
		return (false);
	for (i = phash(p, m->cap); m->k[i] != NULL; i = (i + 1) & (m->cap - 1))
		if (m->k[i] == p) {
			*vp = m->v[i];
			return (true);
		}
	return (false);
}

static void
pmap_put(struct pmap *m, const void *p, size_t v)
{
	struct pmap old = *m;
	size_t i;

	if ((m->n + 1) * 2 > m->cap) {
		m->cap = m->cap == 0 ? 256 : m->cap * 2;
		m->k = xcalloc(m->cap, sizeof(*m->k));
		m->v = xcalloc(m->cap, sizeof(*m->v));
		m->n = 0;
		for (i = 0; i < old.cap; i++)
			if (old.k[i] != NULL)
				pmap_put(m, old.k[i], old.v[i]);
		free(old.k);
		free(old.v);
	}
	for (i = phash(p, m->cap); m->k[i] != NULL; i = (i + 1) & (m->cap - 1))
		;
	m->k[i] = p;
	m->v[i] = v;
	m->n++;
}

/* A C string literal, every byte that is not plain ASCII escaped. */
static void
cstr(struct buf *b, const char *s)
{

	if (s == NULL) {
		buf_puts(b, "NULL");
		return;
	}
	buf_puts(b, "\"");
	for (; *s != '\0'; s++) {
		unsigned char c = (unsigned char)*s;

		if (c == '"' || c == '\\')
			buf_printf(b, "\\%c", c);
		else if (c == '\n')
			buf_puts(b, "\\n");
		else if (c == '\t')
			buf_puts(b, "\\t");
		else if (c < 0x20 || c >= 0x7f)
			buf_printf(b, "\\%03o", c);
		else
			buf_add(b, (const char *)&c, 1);
	}
	buf_puts(b, "\"");
}

/* CBL_YNF_DENY_WRITE and _ALL: NACM's extensions on the node. */
static unsigned
nacm_flags(const struct snode *n)
{
	unsigned f = 0;

	for (size_t i = 0; i < n->nexts; i++) {
		if (strcmp(n->exts[i].ext,
		    "ietf-netconf-acm:default-deny-write") == 0)
			f |= 0x0080;
		else if (strcmp(n->exts[i].ext,
		    "ietf-netconf-acm:default-deny-all") == 0)
			f |= 0x0100;
	}
	return (f);
}

/* An expression's number: the same text, the same number. */
static int32_t
xpath_id(struct ys *y, const char *x)
{

	for (size_t i = 0; i < y->nxp; i++)
		if (strcmp(y->xp[i], x) == 0)
			return ((int32_t)i);
	y->xp = xreallocarray(y->xp, y->nxp + 1, sizeof(*y->xp));
	y->xp[y->nxp] = xstrdup(x);
	return ((int32_t)y->nxp++);
}

static const int ytype_kind[] = {
	[ST_BINARY] = CBL_YT_BINARY, [ST_BITS] = CBL_YT_BITS,
	[ST_BOOLEAN] = CBL_YT_BOOLEAN, [ST_DECIMAL64] = CBL_YT_DECIMAL64,
	[ST_EMPTY] = CBL_YT_EMPTY, [ST_ENUMERATION] = CBL_YT_ENUMERATION,
	[ST_IDENTITYREF] = CBL_YT_IDENTITYREF,
	[ST_INSTANCEID] = CBL_YT_INSTANCEID, [ST_INT8] = CBL_YT_INT8,
	[ST_INT16] = CBL_YT_INT16, [ST_INT32] = CBL_YT_INT32,
	[ST_INT64] = CBL_YT_INT64, [ST_STRING] = CBL_YT_STRING,
	[ST_UINT8] = CBL_YT_UINT8, [ST_UINT16] = CBL_YT_UINT16,
	[ST_UINT32] = CBL_YT_UINT32, [ST_UINT64] = CBL_YT_UINT64,
	[ST_UNION] = CBL_YT_UNION,
};

static const char *const ytype_name[] = {
	[CBL_YT_BINARY] = "CBL_YT_BINARY", [CBL_YT_BITS] = "CBL_YT_BITS",
	[CBL_YT_BOOLEAN] = "CBL_YT_BOOLEAN",
	[CBL_YT_DECIMAL64] = "CBL_YT_DECIMAL64",
	[CBL_YT_EMPTY] = "CBL_YT_EMPTY",
	[CBL_YT_ENUMERATION] = "CBL_YT_ENUMERATION",
	[CBL_YT_IDENTITYREF] = "CBL_YT_IDENTITYREF",
	[CBL_YT_INSTANCEID] = "CBL_YT_INSTANCEID",
	[CBL_YT_INT8] = "CBL_YT_INT8", [CBL_YT_INT16] = "CBL_YT_INT16",
	[CBL_YT_INT32] = "CBL_YT_INT32", [CBL_YT_INT64] = "CBL_YT_INT64",
	[CBL_YT_STRING] = "CBL_YT_STRING", [CBL_YT_UINT8] = "CBL_YT_UINT8",
	[CBL_YT_UINT16] = "CBL_YT_UINT16", [CBL_YT_UINT32] = "CBL_YT_UINT32",
	[CBL_YT_UINT64] = "CBL_YT_UINT64", [CBL_YT_UNION] = "CBL_YT_UNION",
};

/* A range or a length, as an initializer; its parts defined before. */
static void
restrict_emit(struct ys *y, struct buf *init, const char *what,
    const struct srange *r, bool sgn, size_t tn)
{
	struct buf parts;

	if (r == NULL || r->nparts == 0)
		return;
	buf_init(&parts);
	for (size_t i = 0; i < r->nparts; i++)
		if (sgn)
			buf_printf(&parts, "\t{ .min.i = INT64_C(%" PRId64 "), "
			    ".max.i = INT64_C(%" PRId64 ") },\n",
			    r->parts[i].min.i, r->parts[i].max.i);
		else
			buf_printf(&parts, "\t{ .min.u = UINT64_C(%" PRIu64 "), "
			    ".max.u = UINT64_C(%" PRIu64 ") },\n",
			    r->parts[i].min.u, r->parts[i].max.u);
	buf_printf(&y->types, "static const struct cbl_yrange t%zu_%c[] = {\n"
	    "%s};\n", tn, what[0], parts.p);
	y->mbytes += r->nparts * sizeof(struct cbl_yrange);
	buf_printf(init, "\t.%s = { t%zu_%c, %zu, ", what, tn, what[0],
	    r->nparts);
	cstr(init, r->emsg);
	buf_puts(init, ", ");
	cstr(init, r->eapptag);
	buf_puts(init, " },\n");
	buf_free(&parts);
}

/* What makes two types the same: everything the table says of them. */
static void
type_key(struct buf *k, const struct sntype *t)
{

	if (t->base == ST_LEAFREF && t->real != NULL) {
		buf_printf(k, "leafref(%s,%d)", t->cpath != NULL ? t->cpath : "",
		    t->require_instance);
		type_key(k, t->real);
		return;
	}
	buf_printf(k, "%d/%u/%d", t->base, t->fdigits, t->require_instance);
	for (size_t i = 0; t->range != NULL && i < t->range->nparts; i++)
		buf_printf(k, "r%" PRIx64 ":%" PRIx64,
		    t->range->parts[i].min.u, t->range->parts[i].max.u);
	if (t->range != NULL)
		buf_printf(k, "e%s|%s", t->range->emsg != NULL ?
		    t->range->emsg : "", t->range->eapptag != NULL ?
		    t->range->eapptag : "");
	for (size_t i = 0; t->length != NULL && i < t->length->nparts; i++)
		buf_printf(k, "l%" PRIx64 ":%" PRIx64,
		    t->length->parts[i].min.u, t->length->parts[i].max.u);
	if (t->length != NULL)
		buf_printf(k, "e%s|%s", t->length->emsg != NULL ?
		    t->length->emsg : "", t->length->eapptag != NULL ?
		    t->length->eapptag : "");
	for (size_t i = 0; i < t->npatterns; i++)
		buf_printf(k, "p%d%s|%s|%s", t->patterns[i].invert,
		    t->patterns[i].expr, t->patterns[i].emsg != NULL ?
		    t->patterns[i].emsg : "", t->patterns[i].eapptag != NULL ?
		    t->patterns[i].eapptag : "");
	for (size_t i = 0; i < t->nitems; i++)
		buf_printf(k, "i%s=%" PRId64, t->items[i].name,
		    t->items[i].value);
	for (size_t i = 0; i < t->nbases; i++)
		buf_printf(k, "b%s:%s", t->bases[i]->module->name,
		    t->bases[i]->name);
	for (size_t i = 0; i < t->nmembers; i++) {
		buf_puts(k, "m(");
		type_key(k, t->members[i]);
		buf_puts(k, ")");
	}
}

/* A type's number: made once, its members before it. */
/*
 * A value's C type, as gen_yang_h() declares it for a node whose struct
 * name (the enum's, the union struct's) is cn.
 */
static void
c_type(struct buf *b, const struct sntype *t, const char *cn)
{

	switch (t->base) {
	case ST_BINARY:
	case ST_BITS:
	case ST_INSTANCEID:
		buf_puts(b, "struct cbl_bytes");
		break;
	case ST_BOOLEAN:
	case ST_EMPTY:
		buf_puts(b, "bool");
		break;
	case ST_DECIMAL64:
	case ST_INT64:
		buf_puts(b, "int64_t");
		break;
	case ST_ENUMERATION:
		/* An annotation's has no C name: an int holds it. */
		if (cn != NULL)
			buf_printf(b, "enum %s", cn);
		else
			buf_puts(b, "int");
		break;
	case ST_IDENTITYREF:
	case ST_UINT64:
		buf_puts(b, "uint64_t");
		break;
	case ST_INT8:
		buf_puts(b, "int8_t");
		break;
	case ST_INT16:
		buf_puts(b, "int16_t");
		break;
	case ST_INT32:
		buf_puts(b, "int32_t");
		break;
	case ST_LEAFREF:
		if (t->real != NULL)
			c_type(b, t->real, cn);
		else
			buf_puts(b, "int");
		break;
	case ST_STRING:
		buf_puts(b, "const char *");
		break;
	case ST_UINT8:
		buf_puts(b, "uint8_t");
		break;
	case ST_UINT16:
		buf_puts(b, "uint16_t");
		break;
	case ST_UINT32:
		buf_puts(b, "uint32_t");
		break;
	case ST_UNION:
		buf_printf(b, "struct %s", cn);
		break;
	}
}

static size_t
type_ref(struct ys *y, const struct sntype *t, const char *where,
    const char *cn)
{
	const struct sntype *real;
	struct buf key, init, list;
	size_t tn, *mem = NULL;
	char why[256];
	size_t pos;

	buf_init(&key);
	type_key(&key, t);
	for (tn = 0; tn < y->ntypes; tn++)
		if (strcmp(y->tkeys[tn], key.p) == 0) {
			buf_free(&key);
			return (tn);
		}
	real = t->base == ST_LEAFREF && t->real != NULL ? t->real : t;
	if (real->base == ST_LEAFREF) {
		diag_add(y->d, 0, 0, "%s: a leafref without its target's type",
		    where);
		real = NULL;
	}
	if (real != NULL && real->nmembers > 0) {
		mem = xcalloc(real->nmembers, sizeof(*mem));
		for (size_t i = 0; i < real->nmembers; i++) {
			char *mcn = xasprintf("%s_m%zu", cn, i);

			mem[i] = type_ref(y, real->members[i], where, mcn);
			free(mcn);
		}
	}
	tn = y->ntypes++;
	y->tkeys = xreallocarray(y->tkeys, y->ntypes, sizeof(*y->tkeys));
	y->tkeys[tn] = key.p;
	y->mtypes++;
	y->mbytes += sizeof(struct cbl_ytype);
	if (real == NULL) {
		buf_printf(&y->types, "static const struct cbl_ytype t%zu;\n",
		    tn);
		return (tn);
	}

	buf_init(&init);
	buf_printf(&init, "\t.kind = %s,\n", ytype_name[ytype_kind[real->base]]);
	/* Its C size, as the structs have it; a union's v. */
	buf_init(&list);
	c_type(&list, real, cn);
	buf_printf(&init, "\t.csize = sizeof(%s),\n", list.p);
	if (real->base == ST_UNION)
		buf_printf(&init, "\t.voff = offsetof(%s, v),\n", list.p);
	buf_free(&list);
	/* require-instance: a leafref's own, an instance-identifier's. */
	if (t != real && t->require_instance)
		buf_puts(&init, "\t.flags = CBL_YTF_LEAFREF | CBL_YTF_REQUIRE,\n");
	else if (t != real)
		buf_puts(&init, "\t.flags = CBL_YTF_LEAFREF,\n");
	else if (real->base == ST_INSTANCEID && real->require_instance)
		buf_puts(&init, "\t.flags = CBL_YTF_REQUIRE,\n");
	if (real->fdigits != 0)
		buf_printf(&init, "\t.fdigits = %u,\n", real->fdigits);
	/* The expressions by module (xp_canon()), which the tables resolve. */
	buf_printf(&init, "\t.path = %d,\n", t != real && t->cpath != NULL ?
	    xpath_id(y, t->cpath) : -1);
	restrict_emit(y, &init, "range", real->range,
	    sntype_signed(real->base), tn);
	restrict_emit(y, &init, "length", real->length, false, tn);
	if (real->npatterns > 0) {
		buf_init(&list);
		for (size_t i = 0; i < real->npatterns; i++) {
			const struct spattern *p = &real->patterns[i];
			char *ere;

			if ((ere = cbl_pattern_ere(p->expr, why, sizeof(why),
			    &pos)) == NULL) {
				diag_add(y->d, 0, 0, "%s: pattern '%s': %s",
				    where, p->expr, why);
				continue;
			}
			buf_puts(&list, "\t{ ");
			cstr(&list, p->expr);
			buf_puts(&list, ", ");
			cstr(&list, ere);
			buf_printf(&list, ", %s, ", p->invert ? "true" :
			    "false");
			cstr(&list, p->emsg);
			buf_puts(&list, ", ");
			cstr(&list, p->eapptag);
			buf_puts(&list, " },\n");
			y->mbytes += sizeof(struct cbl_ypattern) +
			    strlen(p->expr) + strlen(ere) + 2;
			free(ere);
		}
		buf_printf(&y->types, "static const struct cbl_ypattern "
		    "t%zu_p[] = {\n%s};\n", tn, list.p != NULL ? list.p : "");
		buf_printf(&init, "\t.npatterns = %zu,\n\t.patterns = t%zu_p,\n",
		    real->npatterns, tn);
		buf_free(&list);
	}
	if (real->nitems > 0) {
		buf_init(&list);
		for (size_t i = 0; i < real->nitems; i++) {
			buf_puts(&list, "\t{ ");
			cstr(&list, real->items[i].name);
			buf_printf(&list, ", INT64_C(%" PRId64 ") },\n",
			    real->items[i].value);
			y->mbytes += sizeof(struct cbl_yitem) +
			    strlen(real->items[i].name) + 1;
		}
		buf_printf(&y->types, "static const struct cbl_yitem "
		    "t%zu_i[] = {\n%s};\n", tn, list.p);
		buf_printf(&init, "\t.nitems = %zu,\n\t.items = t%zu_i,\n",
		    real->nitems, tn);
		buf_free(&list);
	}
	if (real->nmembers > 0) {
		buf_init(&list);
		for (size_t i = 0; i < real->nmembers; i++)
			buf_printf(&list, "%s&t%zu", i > 0 ? ", " : "", mem[i]);
		buf_printf(&y->types, "static const struct cbl_ytype *const "
		    "t%zu_m[] = { %s };\n", tn, list.p);
		buf_printf(&init, "\t.nmembers = %zu,\n\t.members = t%zu_m,\n",
		    real->nmembers, tn);
		y->mbytes += real->nmembers * sizeof(void *);
		buf_free(&list);
	}
	if (real->nbases > 0) {
		buf_init(&list);
		for (size_t i = 0; i < real->nbases; i++) {
			if (real->bases[i]->sid == 0)
				diag_add(y->d, 0, 0, "%s: identity %s:%s, a "
				    "base, has no SID", where,
				    real->bases[i]->module->name,
				    real->bases[i]->name);
			if (!pmap_get(&y->bases, real->bases[i], &pos)) {
				pmap_put(&y->bases, real->bases[i], y->nbase);
				y->basev = xreallocarray(y->basev, y->nbase + 1,
				    sizeof(*y->basev));
				y->basev[y->nbase++] = real->bases[i];
			}
			buf_printf(&list, "%sUINT64_C(%" PRIu64 ")", i > 0 ?
			    ", " : "", real->bases[i]->sid);
		}
		buf_printf(&y->types, "static const uint64_t t%zu_b[] = { %s };"
		    "\n", tn, list.p);
		buf_printf(&init, "\t.nbases = %zu,\n\t.bases = t%zu_b,\n",
		    real->nbases, tn);
		y->mbytes += real->nbases * sizeof(uint64_t);
		buf_free(&list);
	}
	buf_printf(&y->types, "static const struct cbl_ytype t%zu = {\n%s};\n\n",
	    tn, init.p);
	buf_free(&init);
	free(mem);
	return (tn);
}

/* A data node to the tables: not a choice, a case, or libyang's own. */
static bool
tabled(const struct snode *n)
{

	return (n->kind != SN_CHOICE && n->kind != SN_CASE &&
	    (n->flags & SNF_INTERNAL) == 0);
}

/* The children of a node, choices and cases passed through. */
struct kids {
	const struct snode **v;
	size_t		 n;
};

static void
kids_add(struct kids *k, const struct snode *first)
{

	for (const struct snode *c = first; c != NULL; c = c->next) {
		if (c->kind == SN_CHOICE || c->kind == SN_CASE)
			kids_add(k, c->child);
		else if (tabled(c)) {
			k->v = xreallocarray(k->v, k->n + 1, sizeof(*k->v));
			k->v[k->n++] = c;
		}
	}
}

static int
by_sid(const void *a, const void *b)
{
	const struct snode *x = *(const struct snode *const *)a;
	const struct snode *y = *(const struct snode *const *)b;

	return ((x->sid > y->sid) - (x->sid < y->sid));
}

static void
whens_emit(struct ys *y, const struct snode *n, const char *name)
{
	struct buf list;

	if (n->nwhen == 0)
		return;
	buf_init(&list);
	for (size_t i = 0; i < n->nwhen; i++)
		buf_printf(&list, "\t{ %d, %s },\n", xpath_id(y, n->cwhen[i]),
		    n->whenctx[i] == SWC_SELF ? "CBL_YWC_SELF" :
		    n->whenctx[i] == SWC_ROOT ? "CBL_YWC_ROOT" :
		    "CBL_YWC_PARENT");
	buf_printf(&y->body, "static const struct cbl_ywhen %s[] = {\n%s};\n",
	    name, list.p);
	y->mbytes += n->nwhen * sizeof(struct cbl_ywhen);
	buf_free(&list);
}

/* The choice c is: its cases, and the choice it is in, made first. */
static size_t
choice_ref(struct ys *y, const struct snode *c)
{
	const struct snode *pc, *k;
	struct buf init, list, w;
	size_t cn, pn = 0, ncases, i, dflt;
	bool in_choice;

	if (pmap_get(&y->choices, c, &cn))
		return (cn);
	/* A choice in a case of another, under the same data node. */
	pc = c->parent;
	in_choice = pc != NULL && pc->kind == SN_CASE && pc->parent != NULL &&
	    pc->parent->kind == SN_CHOICE;
	if (in_choice)
		pn = choice_ref(y, pc->parent);
	cn = y->nchoices++;
	pmap_put(&y->choices, c, cn);

	buf_init(&list);
	ncases = 0;
	dflt = SIZE_MAX;
	for (k = c->child, i = 0; k != NULL; k = k->next, i++) {
		buf_init(&w);
		buf_printf(&w, "c%zu_w%zu", cn, i);
		whens_emit(y, k, w.p);
		buf_puts(&list, "\t{ ");
		cstr(&list, k->name);
		if (k->nwhen > 0)
			buf_printf(&list, ", %s, %zu },\n", w.p, k->nwhen);
		else
			buf_puts(&list, ", NULL, 0 },\n");
		if (k == c->dflt_case)
			dflt = i;
		buf_free(&w);
		ncases++;
		y->mbytes += sizeof(struct cbl_ycase) + strlen(k->name) + 1;
	}
	buf_printf(&y->body, "static const struct cbl_ycase c%zu_c[] = {\n%s"
	    "};\n", cn, list.p != NULL ? list.p : "");
	buf_free(&list);
	buf_init(&w);
	buf_printf(&w, "c%zu_w", cn);
	whens_emit(y, c, w.p);
	buf_init(&init);
	buf_puts(&init, "\t.name = ");
	cstr(&init, c->name);
	buf_puts(&init, ",\n");
	if (in_choice) {
		for (k = pc->parent->child, i = 0; k != NULL && k != pc;
		    k = k->next)
			i++;
		buf_printf(&init, "\t.parent = &c%zu,\n\t.parent_case = %zu,\n",
		    pn, i);
	}
	buf_printf(&init, "\t.ncases = %zu,\n\t.cases = c%zu_c,\n"
	    "\t.dflt = %d,\n", ncases, cn, dflt == SIZE_MAX ? -1 : (int)dflt);
	/* Its enum, in the struct its nodes are members of. */
	buf_init(&list);
	if (member_of(&list, c)) {
		struct buf mb;

		buf_init(&mb);
		yc_member(&mb, c);
		buf_printf(&init, "\t.off = offsetof(%s, %s),\n", list.p, mb.p);
		buf_free(&mb);
	} else
		buf_puts(&init, "\t.off = CBL_YOFF_NONE,\n");
	buf_free(&list);
	if (c->flags & SNF_MANDATORY)
		buf_puts(&init, "\t.mandatory = true,\n");
	if (c->nwhen > 0)
		buf_printf(&init, "\t.when = %s,\n\t.nwhen = %zu,\n", w.p,
		    c->nwhen);
	buf_printf(&y->body, "static const struct cbl_ychoice c%zu = {\n%s};\n"
	    "\n", cn, init.p);
	y->mbytes += sizeof(struct cbl_ychoice) + strlen(c->name) + 1;
	buf_free(&init);
	buf_free(&w);
	return (cn);
}

static const char *const ynode_kind[] = {
	[SN_CONTAINER] = "CBL_YN_CONTAINER", [SN_LEAF] = "CBL_YN_LEAF",
	[SN_LEAFLIST] = "CBL_YN_LEAFLIST", [SN_LIST] = "CBL_YN_LIST",
	[SN_ANYDATA] = "CBL_YN_ANYDATA", [SN_ANYXML] = "CBL_YN_ANYXML",
	[SN_RPC] = "CBL_YN_RPC", [SN_ACTION] = "CBL_YN_ACTION",
	[SN_NOTIF] = "CBL_YN_NOTIF", [SN_INPUT] = "CBL_YN_INPUT",
	[SN_OUTPUT] = "CBL_YN_OUTPUT",
};

static size_t	node_ref(struct ys *y, const struct snode *n);

/*
 * The children array of node nn, from first, by SID; the keys, as
 * indices in it, when the node is a list.  Returns how many.
 */
static size_t
children_emit(struct ys *y, size_t nn, const struct snode *first,
    const struct snode *list, struct buf *init)
{
	struct kids k = { 0 };
	struct buf arr;
	size_t *num;

	kids_add(&k, first);
	if (k.n == 0)
		return (0);
	qsort(k.v, k.n, sizeof(*k.v), by_sid);
	map_emit(y, nn, k.v, k.n, init);
	num = xcalloc(k.n, sizeof(*num));
	for (size_t i = 0; i < k.n; i++) {
		if (i > 0 && k.v[i]->sid == k.v[i - 1]->sid && k.v[i]->sid !=
		    0)
			diag_add(y->d, 0, 0, "%s and %s: one SID, %" PRIu64,
			    k.v[i - 1]->name, k.v[i]->name, k.v[i]->sid);
		num[i] = node_ref(y, k.v[i]);
	}
	buf_init(&arr);
	for (size_t i = 0; i < k.n; i++)
		buf_printf(&arr, "%s&n%zu", i % 6 == 0 ? (i > 0 ? ",\n\t" :
		    "\t") : ", ", num[i]);
	buf_printf(&y->body, "static const struct cbl_ynode *const n%zu_c[] = "
	    "{\n%s\n};\n", nn, arr.p);
	buf_printf(init, "\t.nchild = %zu,\n\t.child = n%zu_c,\n", k.n, nn);
	y->mbytes += k.n * sizeof(void *);
	if (list != NULL && list->nkeys > 0) {
		arr.len = 0;
		arr.p[0] = '\0';
		for (size_t i = 0; i < list->nkeys; i++) {
			size_t j;

			for (j = 0; j < k.n && k.v[j] != list->keys[i]; j++)
				;
			buf_printf(&arr, "%s%zu", i > 0 ? ", " : "", j);
		}
		buf_printf(&y->body, "static const uint32_t n%zu_k[] = { %s };"
		    "\n", nn, arr.p);
		buf_printf(init, "\t.nkeys = %zu,\n\t.keys = n%zu_k,\n",
		    list->nkeys, nn);
		y->mbytes += list->nkeys * sizeof(uint32_t);
	}
	buf_free(&arr);
	free(num);
	free(k.v);
	return (k.n);
}

/*
 * A list's unique statements: for each leaf, its data nodes from the
 * list entry down, choices and cases left out, as the structs nest.
 */
static void
unique_emit(struct ys *y, size_t nn, const struct snode *list,
    struct buf *init)
{
	struct buf set;

	buf_init(&set);
	for (size_t i = 0; i < list->nuniques; i++) {
		const struct sunique *un = &list->uniques[i];
		struct buf leaves;

		buf_init(&leaves);
		for (size_t j = 0; j < un->n; j++) {
			const struct snode *chain[64];
			size_t depth = 0;
			struct buf path;

			if (un->leaf[j] == NULL) {
				diag_add(y->d, 0, 0, "%s: a unique leaf not "
				    "found below the list", list->name);
				continue;
			}
			for (const struct snode *x = un->leaf[j];
			    x != NULL && x != list; x = x->parent)
				if (x->kind != SN_CHOICE && x->kind != SN_CASE &&
				    depth < sizeof(chain) / sizeof(chain[0]))
					chain[depth++] = x;
			buf_init(&path);
			while (depth > 0)
				buf_printf(&path, "&n%zu, ",
				    node_ref(y, chain[--depth]));
			buf_printf(&y->body, "static const struct cbl_ynode "
			    "*const n%zu_u%zu_%zu[] = { %sNULL };\n", nn, i, j,
			    path.p);
			buf_printf(&leaves, "%sn%zu_u%zu_%zu", j > 0 ? ", " : "",
			    nn, i, j);
			buf_free(&path);
			y->mbytes += sizeof(void *) * 2;
		}
		buf_printf(&y->body, "static const struct cbl_ynode *const "
		    "*const n%zu_u%zu[] = { %s };\n", nn, i, leaves.p);
		buf_printf(&set, "%s{ %zu, n%zu_u%zu }", i > 0 ? ", " : "",
		    un->n, nn, i);
		buf_free(&leaves);
	}
	buf_printf(&y->body, "static const struct cbl_yunique n%zu_q[] = { %s };"
	    "\n", nn, set.p);
	buf_printf(init, "\t.nunique = %zu,\n\t.unique = n%zu_q,\n",
	    list->nuniques, nn);
	y->mbytes += list->nuniques * sizeof(struct cbl_yunique);
	buf_free(&set);
}

/*
 * How a node's children are found by delta (cbl_ynode_child()): the
 * leading ones within a span of a few times their number, dense when
 * their SIDs follow one another, else by a table of their places; the
 * rest, and all when fewer than four lie close, by a binary search.
 */
#define	MAP_SPAN(n)	((n) * 8 + 16)

static void
map_emit(struct ys *y, size_t nn, const struct snode **v, size_t n,
    struct buf *init)
{
	uint64_t s0 = v[0]->sid, span;
	size_t m, i;

	for (m = 0; m < n && v[m]->sid - s0 < MAP_SPAN(n) && v[m]->sid -
	    s0 < UINT16_MAX; m++)
		;
	span = v[m - 1]->sid - s0 + 1;
	if (span == m) {
		buf_printf(init, "\t.nmap = %zu,\n", m);
		y->ndense++;
		return;
	}
	if (m < 4) {
		y->nsearched++;
		return;
	}
	buf_printf(&y->body, "static const uint16_t n%zu_p[] = {", nn);
	for (uint64_t at = 0; at < span; at++) {
		/* Its place, from 1, or 0 for a SID that is no child's. */
		for (i = 0; i < m && v[i]->sid - s0 < at; i++)
			;
		buf_printf(&y->body, "%s%zu", at == 0 ? "\n\t" : at % 16 == 0 ?
		    ",\n\t" : ", ", i < m && v[i]->sid - s0 == at ? i + 1 : 0);
	}
	buf_puts(&y->body, "\n};\n");
	buf_printf(init, "\t.nmap = %ju,\n\t.map = n%zu_p,\n", (uintmax_t)span,
	    nn);
	y->mbytes += span * sizeof(uint16_t);
	y->nmapped++;
}

/* The data node above n, past choices and cases; NULL at the top. */
static const struct snode *
data_parent(const struct snode *n)
{
	const struct snode *p = n->parent;

	while (p != NULL && (p->kind == SN_CHOICE || p->kind == SN_CASE))
		p = p->parent;
	return (p);
}

/*
 * The struct n is a member of, as gen_yang_h() writes it: its data
 * parent's, its structure's, its module's data; false for a node that
 * is in none (an rpc, an action, a notification, an input, an output),
 * or under an rpc or an action itself.
 */
static bool
member_of(struct buf *b, const struct snode *n)
{
	const struct snode *p;

	switch (n->kind) {
	case SN_CONTAINER:
	case SN_LEAF:
	case SN_LEAFLIST:
	case SN_LIST:
	case SN_ANYDATA:
	case SN_ANYXML:
	case SN_CHOICE:
		break;
	default:
		return (false);
	}
	if ((p = data_parent(n)) != NULL) {
		if (p->kind == SN_RPC || p->kind == SN_ACTION)
			return (false);
		buf_puts(b, "struct ");
		yc_struct(b, p);
	} else if (n->in != NULL) {
		buf_puts(b, "struct ");
		yc_mangle(b, n->in->module->name);
		buf_puts(b, "_");
		yc_mangle(b, n->in->arg);
	} else {
		buf_puts(b, "struct ");
		yc_mangle(b, n->module->name);
	}
	return (true);
}

/* Whether n has a struct of its own. */
static bool
has_struct(const struct snode *n)
{

	return (n->kind == SN_CONTAINER || n->kind == SN_LIST ||
	    n->kind == SN_NOTIF || n->kind == SN_INPUT || n->kind == SN_OUTPUT);
}

/* A struct's encoder and decoder: the codec with its node, nn. */
static void
codec_emit(struct ys *y, const char *sname, size_t nn)
{

	buf_printf(&y->codec, "int\n%s_encode(const struct %s *p, struct "
	    "cbl_ybuf *b)\n{\n\n\treturn (cbl_yencode(&n%zu, p, b));\n}\n\n"
	    "int\n%s_decode(const void *data, size_t len, struct %s *p,\n"
	    "    cbl_yarena *a, int flags, char *why, size_t whylen)\n{\n\n"
	    "\tmemset(p, 0, sizeof(*p));\n\treturn (cbl_ydecode(&n%zu, data, "
	    "len, p, a, flags, why, whylen));\n}\n\n", sname, sname, nn, sname,
	    sname, nn);
	/* In a message: {SID: value}, an input or output under its rpc's. */
	buf_printf(&y->codec, "int\n%s_put(cbl_msg *m, const struct %s *p)\n"
	    "{\n\n\treturn (cbl_msg_put_ynode(m, &n%zu, p));\n}\n\n"
	    "int\n%s_parse(const cbl_msg *m, struct %s *p, cbl_yarena *a,\n"
	    "    int flags, char *why, size_t whylen)\n{\n\n\treturn "
	    "(cbl_msg_ydecode(m, &n%zu, p, a, flags, why, whylen));\n}\n\n",
	    sname, sname, nn, sname, sname, nn);
}

/*
 * rpc_call(conn, in, out, a, timeout): RPC of family 1, the input put,
 * the output read back (cbl_schema.h).
 */
static void
call_emit(struct ys *y, const struct snode *out, size_t onn)
{
	const struct snode *in = NULL;
	struct buf fn, is, os;

	for (const struct snode *c = out->parent->child; c != NULL;
	    c = c->next)
		if (c->kind == SN_INPUT)
			in = c;
	if (in == NULL)
		return;
	buf_init(&fn);
	buf_init(&is);
	buf_init(&os);
	yc_struct(&fn, out->parent);
	yc_struct(&is, in);
	yc_struct(&os, out);
	buf_printf(&y->codec, "int\n%s_call(cbl_conn *c, const struct %s *in,\n"
	    "    struct %s *out, cbl_yarena *a, int timeout_ms)\n{\n"
	    "\tcbl_msg *m, *r;\n\tint error;\n\n"
	    "\tif ((error = cbl_msg_new(cbl_conn_ctx(c), CBL_YANG_FAMILY,\n"
	    "\t    CBL_YCMD_RPC, 0, &m)) != 0)\n\t\treturn (error);\n"
	    "\tif ((error = cbl_msg_put_ynode(m, &n%zu, in)) != 0) {\n"
	    "\t\tcbl_msg_free(m);\n\t\treturn (error);\n\t}\n"
	    "\tif ((error = cbl_request(c, m, &r, timeout_ms)) == 0)\n"
	    "\t\terror = cbl_msg_ydecode(r, &n%zu, out, a, CBL_YD_STRICT, "
	    "NULL,\n\t\t    0);\n\tcbl_msg_free(r);\n\treturn (error);\n}"
	    "\n\n", fn.p, is.p, os.p, node_ref(y, in), onn);
	buf_free(&fn);
	buf_free(&is);
	buf_free(&os);
}

/* The path of n, for what is said about it. */
static void
where_of(struct buf *b, const struct snode *n)
{

	if (!snode_sid_path(n, b))
		buf_printf(b, "%s:%s", n->module->name, n->name);
}

/* A node's number: made with its children. */
static size_t
node_ref(struct ys *y, const struct snode *n)
{
	const struct snode *c;
	struct buf init, list, w, where;
	size_t nn, mn;

	if (pmap_get(&y->nodes, n, &nn))
		return (nn);
	nn = y->nnodes++;
	pmap_put(&y->nodes, n, nn);
	top_add(&y->all, &y->nall, nn, n->sid);
	y->mnodes++;
	y->mbytes += sizeof(struct cbl_ynode) + strlen(n->name) + 1;
	buf_init(&where);
	where_of(&where, n);
	if (n->sid == 0)
		diag_add(y->d, 0, 0, "%s: no SID: its module's .sid file (-s) "
		    "gives it one, cblink-gen -a numbers it", where.p);

	buf_init(&init);
	buf_printf(&init, "\t.sid = UINT64_C(%" PRIu64 "),\n\t.name = ",
	    n->sid);
	cstr(&init, n->name);
	buf_printf(&init, ",\n\t.kind = %s,\n", ynode_kind[n->kind]);
	/* An input's and an output's deltas are from the rpc's SID. */
	if ((n->kind == SN_INPUT || n->kind == SN_OUTPUT) && n->parent != NULL)
		buf_printf(&init, "\t.base = UINT64_C(%" PRIu64 "),\n",
		    n->parent->sid);
	if ((n->flags & 0x7f) != 0 || nacm_flags(n) != 0 || snode_mount(n))
		buf_printf(&init, "\t.flags = 0x%x,\n", (n->flags & 0x7f) |
		    nacm_flags(n) | (snode_mount(n) ? 0x0200 : 0));
	/* Where it is in the structs. */
	buf_init(&list);
	if (member_of(&list, n)) {
		buf_init(&w);
		yc_member(&w, n);
		buf_printf(&init, "\t.off = offsetof(%s, %s),\n", list.p, w.p);
		if (yc_has_flag(n))
			buf_printf(&init, "\t.hoff = offsetof(%s, has_%s),\n",
			    list.p, w.p);
		else
			buf_puts(&init, "\t.hoff = CBL_YOFF_NONE,\n");
		buf_free(&w);
	} else
		buf_puts(&init, "\t.off = CBL_YOFF_NONE,\n"
		    "\t.hoff = CBL_YOFF_NONE,\n");
	buf_free(&list);
	if (has_struct(n)) {
		buf_init(&list);
		yc_struct(&list, n);
		buf_printf(&init, "\t.size = sizeof(struct %s),\n", list.p);
		if (snode_mount(n))
			buf_printf(&init, "\t.moff = offsetof(struct %s, "
			    "mounted),\n", list.p);
		/* A struct several nodes share (cg:struct) has the codec of
		 * the first of them. */
		{
			size_t i;

			for (i = 0; i < y->ncodecs; i++)
				if (strcmp(y->codecs[i], list.p) == 0)
					break;
			if (i == y->ncodecs) {
				y->codecs = xreallocarray(y->codecs, y->ncodecs + 1,
				    sizeof(*y->codecs));
				y->codecs[y->ncodecs++] = xstrdup(list.p);
				codec_emit(y, list.p, nn);
			}
		}
		/* A notification as a server sends it: {SID: value}. */
		if (n->kind == SN_NOTIF)
			buf_printf(&y->codec, "int\n%s_notification(const struct "
			    "%s *p, struct cbl_ybuf *b)\n{\n\n\treturn "
			    "(cbl_yencode_sid(&n%zu, p, b));\n}\n\nint\n"
			    "%s_notify(cbl_ctx *ctx, const struct %s *p)\n{\n\n"
			    "\treturn (cbl_ynotify(ctx, &n%zu, p));\n}\n\n",
			    list.p, list.p, nn, list.p, list.p, nn);
		buf_free(&list);
	}
	/* An rpc's output: the client's call, through family 1. */
	if (n->kind == SN_OUTPUT && n->parent != NULL &&
	    n->parent->kind == SN_RPC)
		call_emit(y, n, nn);
	if (n->type != NULL) {
		struct buf cn;

		buf_init(&cn);
		yc_struct(&cn, n);
		buf_printf(&init, "\t.type = &t%zu,\n", type_ref(y, n->type,
		    where.p, cn.p));
		buf_free(&cn);
	}
	(void)children_emit(y, nn, n->child, n->kind == SN_LIST ? n : NULL,
	    &init);
	/* Its data parent, choices and cases passed over, or its structure. */
	for (c = n->parent; c != NULL && (c->kind == SN_CHOICE ||
	    c->kind == SN_CASE); c = c->parent)
		;
	if (c != NULL)
		buf_printf(&init, "\t.parent = &n%zu,\n", node_ref(y, c));
	else if (n->in != NULL && pmap_get(&y->structs, n->in, &mn))
		buf_printf(&init, "\t.parent = &n%zu,\n", mn);
	/* A leafref's target, where its module's tables are these too. */
	if (n->lref != NULL && smodule_emitted(n->lref->module))
		buf_printf(&init, "\t.lref = &n%zu,\n", node_ref(y, n->lref));
	if (n->kind == SN_LIST && n->nuniques > 0)
		unique_emit(y, nn, n, &init);
	if (n->nwhen > 0) {
		buf_init(&w);
		buf_printf(&w, "n%zu_w", nn);
		whens_emit(y, n, w.p);
		buf_printf(&init, "\t.nwhen = %zu,\n\t.when = %s,\n", n->nwhen,
		    w.p);
		buf_free(&w);
	}
	if (n->nmusts > 0) {
		buf_init(&list);
		for (size_t i = 0; i < n->nmusts; i++) {
			buf_printf(&list, "\t{ %d, ", xpath_id(y,
			    n->musts[i].cexpr));
			cstr(&list, n->musts[i].emsg);
			buf_puts(&list, ", ");
			cstr(&list, n->musts[i].eapptag);
			buf_puts(&list, " },\n");
		}
		buf_printf(&y->body, "static const struct cbl_ymust n%zu_m[] = "
		    "{\n%s};\n", nn, list.p);
		buf_printf(&init, "\t.nmust = %zu,\n\t.must = n%zu_m,\n",
		    n->nmusts, nn);
		y->mbytes += n->nmusts * sizeof(struct cbl_ymust);
		buf_free(&list);
	}
	if (n->ndflts > 0) {
		buf_init(&list);
		for (size_t i = 0; i < n->ndflts; i++) {
			buf_puts(&list, i > 0 ? ", " : "");
			cstr(&list, n->dflts[i]);
			y->mbytes += strlen(n->dflts[i]) + 1 + sizeof(void *);
		}
		buf_printf(&y->body, "static const char *const n%zu_d[] = { %s "
		    "};\n", nn, list.p);
		buf_printf(&init, "\t.ndflt = %zu,\n\t.dflt = n%zu_d,\n",
		    n->ndflts, nn);
		buf_free(&list);
	}
	if (n->kind == SN_LIST || n->kind == SN_LEAFLIST) {
		if (n->min != 0)
			buf_printf(&init, "\t.min = %u,\n", n->min);
		if (n->max != 0 && n->max != UINT32_MAX)
			buf_printf(&init, "\t.max = %u,\n", n->max);
	}
	if (n->units != NULL) {
		buf_puts(&init, "\t.units = ");
		cstr(&init, n->units);
		buf_puts(&init, ",\n");
	}
	/* The choice it is in, under the same data node. */
	if ((c = n->parent) != NULL && c->kind == SN_CASE && c->parent !=
	    NULL && c->parent->kind == SN_CHOICE) {
		const struct snode *k;
		size_t i;

		for (k = c->parent->child, i = 0; k != NULL && k != c;
		    k = k->next)
			i++;
		buf_printf(&init, "\t.choice = &c%zu,\n\t.ccase = %zu,\n",
		    choice_ref(y, c->parent), i);
	}
	/* Its own module: an augment's nodes are the augmenting one's. */
	(void)pmap_get(&y->mods, n->module, &mn);
	y->mref[mn] = true;
	buf_printf(&y->body, "static const struct cbl_ynode n%zu = {\n%s"
	    "\t.module = &m%zu,\n};\n\n", nn, init.p, mn);
	buf_free(&init);
	buf_free(&where);
	return (nn);
}

/*
 * Identities.
 */

struct iset {
	struct pmap		 in;
	const struct sident	**v;
	size_t			 n;
};

static void
iset_add(struct iset *is, const struct sident *id)
{
	size_t x;

	if (pmap_get(&is->in, id, &x))
		return;
	pmap_put(&is->in, id, is->n);
	is->v = xreallocarray(is->v, is->n + 1, sizeof(*is->v));
	is->v[is->n++] = id;
}

/* Every identity derived from id, directly or not, into is. */
static void
closure(struct iset *is, const struct sident *id)
{
	size_t x;

	for (size_t i = 0; i < id->nderived; i++)
		if (!pmap_get(&is->in, id->derived[i], &x)) {
			iset_add(is, id->derived[i]);
			closure(is, id->derived[i]);
		}
}

static void
iset_free(struct iset *is)
{

	free(is->in.k);
	free(is->in.v);
	free(is->v);
}

static int
ident_cmp(const void *a, const void *b)
{
	const struct sident *x = *(const struct sident *const *)a;
	const struct sident *y = *(const struct sident *const *)b;

	return ((x->sid > y->sid) - (x->sid < y->sid));
}

static int
u64_cmp(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return ((x > y) - (x < y));
}

/*
 * The identity table: the emitted modules' identities, and every one a
 * base has, wherever defined; each with its closure.  Its size.
 */
static size_t
idents_emit(struct ys *y, struct schema *s, struct buf *out)
{
	struct iset all = { 0 };
	struct buf list;
	size_t i, mn;

	for (i = 0; i < s->nmods; i++)
		if (smodule_emitted(s->mods[i]))
			for (size_t j = 0; j < s->mods[i]->nidents; j++)
				iset_add(&all, &s->mods[i]->idents[j]);
	for (i = 0; i < y->nbase; i++) {
		iset_add(&all, y->basev[i]);
		closure(&all, y->basev[i]);
	}
	qsort(all.v, all.n, sizeof(*all.v), ident_cmp);
	buf_init(&list);
	for (i = 0; i < all.n; i++) {
		const struct sident *id = all.v[i];
		struct iset c = { 0 };
		uint64_t *sids;

		if (id->sid == 0)
			diag_add(y->d, 0, 0, "identity %s:%s: no SID: its "
			    "module's .sid file (-s) gives it one",
			    id->module->name, id->name);
		else if (i > 0 && all.v[i - 1]->sid == id->sid)
			diag_add(y->d, 0, 0, "identities %s:%s and %s:%s: one "
			    "SID, %" PRIu64, all.v[i - 1]->module->name,
			    all.v[i - 1]->name, id->module->name, id->name,
			    id->sid);
		closure(&c, id);
		sids = xcalloc(c.n + 1, sizeof(*sids));
		for (size_t j = 0; j < c.n; j++)
			sids[j] = c.v[j]->sid;
		qsort(sids, c.n, sizeof(*sids), u64_cmp);
		if (c.n > 0) {
			buf_printf(out, "static const uint64_t i%zu_d[] = {", i);
			for (size_t j = 0; j < c.n; j++)
				buf_printf(out, "%sUINT64_C(%" PRIu64 ")",
				    j == 0 ? "\n\t" : j % 4 == 0 ? ",\n\t" :
				    ", ", sids[j]);
			buf_puts(out, "\n};\n");
		}
		(void)pmap_get(&y->mods, id->module, &mn);
		y->mref[mn] = true;
		buf_printf(&list, "\t{ UINT64_C(%" PRIu64 "), ", id->sid);
		cstr(&list, id->name);
		buf_printf(&list, ", &m%zu, 0x%x, %zu, ", mn,
		    id->flags & (SNF_DEPRECATED | SNF_OBSOLETE), c.n);
		if (c.n > 0)
			buf_printf(&list, "i%zu_d },\n", i);
		else
			buf_puts(&list, "NULL },\n");
		y->mbytes += sizeof(struct cbl_yident) + strlen(id->name) + 1 +
		    c.n * sizeof(uint64_t);
		free(sids);
		iset_free(&c);
	}
	/* One more, so that the array has one: not counted. */
	buf_printf(out, "static const struct cbl_yident idents[] = {\n%s"
	    "\t{ 0, NULL, NULL, 0, 0, NULL },\n};\n\n", list.p != NULL ?
	    list.p : "");
	buf_free(&list);
	i = all.n;
	iset_free(&all);
	return (i);
}

/* An sx:structure: a node of its own, keyed by the structure's SID. */
static size_t
structure_emit(struct ys *y, const struct smodule *m, size_t mn,
    const struct sext *e)
{
	struct buf init;
	size_t nn;

	nn = y->nnodes++;
	pmap_put(&y->structs, e, nn);
	top_add(&y->all, &y->nall, nn, e->sid);
	y->mnodes++;
	y->mbytes += sizeof(struct cbl_ynode) + strlen(e->arg) + 1;
	if (e->sid == 0)
		diag_add(y->d, 0, 0, "/%s:%s: the structure has no SID: its "
		    "module's .sid file (-s) gives it one", m->name, e->arg);
	buf_init(&init);
	buf_printf(&init, "\t.sid = UINT64_C(%" PRIu64 "),\n\t.name = ", e->sid);
	cstr(&init, e->arg);
	buf_puts(&init, ",\n\t.kind = CBL_YN_STRUCTURE,\n"
	    "\t.off = CBL_YOFF_NONE,\n\t.hoff = CBL_YOFF_NONE,\n");
	{
		struct buf sn;

		buf_init(&sn);
		yc_mangle(&sn, m->name);
		buf_puts(&sn, "_");
		yc_mangle(&sn, e->arg);
		buf_printf(&init, "\t.size = sizeof(struct %s),\n", sn.p);
		codec_emit(y, sn.p, nn);
		buf_free(&sn);
	}
	(void)children_emit(y, nn, e->data, NULL, &init);
	buf_printf(&y->body, "static const struct cbl_ynode n%zu = {\n%s"
	    "\t.module = &m%zu,\n};\n\n", nn, init.p, mn);
	buf_free(&init);
	return (nn);
}

/* An annotation of a module's, and where the tables have it. */
struct annref {
	const struct sext	*e;
	uint64_t		 sid;
	size_t			 mn, i;
};

static int
annot_by_name(const void *a, const void *b)
{

	return (strcmp((*(const struct sext *const *)a)->arg,
	    (*(const struct sext *const *)b)->arg));
}

static int
annot_by_sid(const void *a, const void *b)
{
	const struct annref *x = a, *y = b;

	return ((x->sid > y->sid) - (x->sid < y->sid));
}

/*
 * Module m's annotations (md:annotation), m%zu_a by name; each added to
 * all, for the schema's list by SID.  How many.
 */
static size_t
annots_emit(struct ys *y, const struct smodule *m, size_t mn,
    struct buf *tops, struct annref **all, size_t *nall)
{
	const struct sext **v = NULL;
	size_t n = 0;

	for (size_t i = 0; i < m->nexts; i++)
		if (sext_is_annotation(&m->exts[i], m)) {
			v = xreallocarray(v, n + 1, sizeof(*v));
			v[n++] = &m->exts[i];
		}
	if (n == 0)
		return (0);
	qsort(v, n, sizeof(*v), annot_by_name);
	buf_printf(tops, "static const struct cbl_yannot m%zu_a[] = {\n", mn);
	for (size_t i = 0; i < n; i++) {
		const struct sntype *real = v[i]->type;
		char *where;

		while (real->base == ST_LEAFREF && real->real != NULL)
			real = real->real;
		if (v[i]->sid == 0)
			diag_add(y->d, 0, 0, "annotation %s:%s: no SID: its "
			    "module's .sid file (-s) gives it one", m->name,
			    v[i]->arg);
		if (real->base == ST_UNION || real->base == ST_LEAFREF) {
			diag_add(y->d, 0, 0, "annotation %s:%s: a union or "
			    "leafref type, which an annotation's value cannot "
			    "be held as", m->name, v[i]->arg);
			continue;
		}
		where = xasprintf("annotation %s:%s", m->name, v[i]->arg);
		buf_printf(tops, "\t{ .module = &m%zu, .name = ", mn);
		cstr(tops, v[i]->arg);
		buf_printf(tops, ", .sid = UINT64_C(%" PRIu64 "), .type = "
		    "&t%zu },\n", v[i]->sid, type_ref(y, v[i]->type, where,
		    NULL));
		free(where);
		y->mbytes += sizeof(struct cbl_yannot) + strlen(v[i]->arg) + 1;
		*all = xreallocarray(*all, *nall + 1, sizeof(**all));
		(*all)[(*nall)++] = (struct annref){ v[i], v[i]->sid, mn, i };
	}
	buf_puts(tops, "};\n");
	free(v);
	return (n);
}

static int
top_cmp(const void *a, const void *b)
{
	const struct topn *x = a, *y = b;

	return ((x->sid > y->sid) - (x->sid < y->sid));
}

static void
top_add(struct topn **v, size_t *n, size_t num, uint64_t sid)
{

	*v = xreallocarray(*v, *n + 1, sizeof(**v));
	(*v)[*n].n = num;
	(*v)[(*n)++].sid = sid;
}

int
gen_yang_schema(struct schema *s, const char *base, const char *from,
    struct buf *out, FILE *report, struct diags *d)
{
	struct ys y = { .d = d };
	struct buf tops, head, sizes, nm, idents, bysid;
	struct topn *top;
	struct annref *annots = NULL;
	size_t ntop, total = 0, errs = d->n, i, mn, nident, nannot, nall = 0;
	struct kids k;

	buf_init(&y.types);
	buf_init(&y.codec);
	/* The base as C has it: the tables' name, base_schema. */
	buf_init(&nm);
	buf_puts(&nm, "_");
	for (const char *p = base; *p != '\0'; p++)
		buf_printf(&nm, "%c", (*p >= 'a' && *p <= 'z') || (*p >= 'A' &&
		    *p <= 'Z') || (*p >= '0' && *p <= '9') ? *p : '_');

	buf_init(&y.body);
	buf_init(&tops);
	buf_init(&sizes);
	for (i = 0; i < s->nmods; i++)
		pmap_put(&y.mods, s->mods[i], i);
	y.mref = xcalloc(s->nmods + 1, sizeof(*y.mref));

	for (mn = 0; mn < s->nmods; mn++) {
		const struct smodule *m = s->mods[mn];

		if (!smodule_emitted(m))
			continue;
		y.m = m;
		y.mnodes = y.mtypes = y.mbytes = 0;
		y.mref[mn] = true;
		top = NULL;
		ntop = 0;
		memset(&k, 0, sizeof(k));
		kids_add(&k, m->data);
		kids_add(&k, m->rpcs);
		kids_add(&k, m->notifs);
		for (i = 0; i < k.n; i++)
			top_add(&top, &ntop, node_ref(&y, k.v[i]), k.v[i]->sid);
		free(k.v);
		for (i = 0; i < m->nexts; i++)
			if (sext_is_structure(&m->exts[i], m))
				top_add(&top, &ntop, structure_emit(&y, m, mn,
				    &m->exts[i]), m->exts[i].sid);
		qsort(top, ntop, sizeof(*top), top_cmp);
		if (ntop > 0) {
			buf_printf(&tops, "static const struct cbl_ynode "
			    "*const m%zu_t[] = {\n", mn);
			for (i = 0; i < ntop; i++)
				buf_printf(&tops, "%s&n%zu", i % 6 == 0 ?
				    (i > 0 ? ",\n\t" : "\t") : ", ", top[i].n);
			buf_puts(&tops, "\n};\n");
			y.mbytes += ntop * sizeof(void *);
		}
		y.mbytes += sizeof(struct cbl_ymodule);
		if (m->nfeatures > 0) {
			buf_printf(&tops, "static const struct cbl_yfeature "
			    "m%zu_f[] = {\n", mn);
			for (i = 0; i < m->nfeatures; i++) {
				if (m->features[i].sid == 0)
					diag_add(d, 0, 0, "feature %s:%s: no "
					    "SID: its module's .sid file (-s) "
					    "gives it one", m->name,
					    m->features[i].name);
				buf_printf(&tops, "\t{ UINT64_C(%" PRIu64 "), ",
				    m->features[i].sid);
				cstr(&tops, m->features[i].name);
				buf_printf(&tops, ", %s },\n",
				    m->features[i].enabled ? "true" : "false");
				y.mbytes += sizeof(struct cbl_yfeature) +
				    strlen(m->features[i].name) + 1;
			}
			buf_puts(&tops, "};\n");
		}
		nannot = annots_emit(&y, m, mn, &tops, &annots, &nall);
		buf_printf(&tops, "static const struct cbl_ymodule m%zu = {\n"
		    "\t.schema = &%s_schema,\n\t.name = ", mn, nm.p + 1);
		cstr(&tops, m->name);
		buf_puts(&tops, ",\n\t.revision = ");
		cstr(&tops, m->revision);
		buf_puts(&tops, ",\n\t.ns = ");
		cstr(&tops, m->ns);
		buf_puts(&tops, ",\n\t.prefix = ");
		cstr(&tops, m->prefix);
		buf_printf(&tops, ",\n\t.sid = UINT64_C(%" PRIu64 "),\n", m->sid);
		if (nannot > 0)
			buf_printf(&tops, "\t.nannot = %zu,\n\t.annot = "
			    "m%zu_a,\n", nannot, mn);
		if (m->data != NULL) {
			buf_puts(&tops, "\t.size = sizeof(struct ");
			yc_mangle(&tops, m->name);
			buf_puts(&tops, "),\n");
		}
		if (ntop > 0)
			buf_printf(&tops, "\t.ntop = %zu,\n\t.top = m%zu_t,\n",
			    ntop, mn);
		if (m->nfeatures > 0)
			buf_printf(&tops, "\t.nfeature = %zu,\n\t.feature = "
			    "m%zu_f,\n", m->nfeatures, mn);
		buf_puts(&tops, "};\n\n");
		free(top);
		/* Its trees, what other modules add to them included. */
		buf_printf(&sizes, " * %s: %zu nodes, %zu types, %zu bytes\n",
		    m->name, y.mnodes, y.mtypes, y.mbytes);
		total += y.mbytes;
	}
	/* Every node by SID: a SID is one node's, in all the modules. */
	qsort(y.all, y.nall, sizeof(*y.all), top_cmp);
	buf_init(&bysid);
	for (i = 0; i < y.nall; i++) {
		if (i > 0 && y.all[i].sid == y.all[i - 1].sid)
			diag_add(d, 0, 0, "SID %" PRIu64 " is two nodes' (n%zu "
			    "and n%zu in the tables)", y.all[i].sid,
			    y.all[i - 1].n, y.all[i].n);
		buf_printf(&bysid, "%s&n%zu", i % 6 == 0 ? (i > 0 ? ",\n\t" :
		    "\t") : ", ", y.all[i].n);
	}
	total += y.nall * sizeof(void *);
	/* The identities, after the nodes: their bases are known. */
	buf_init(&idents);
	y.mbytes = 0;
	nident = idents_emit(&y, s, &idents);
	total += y.mbytes;
	/* A module another's nodes are of: named, its tables elsewhere. */
	for (mn = 0; mn < s->nmods; mn++) {
		const struct smodule *m = s->mods[mn];

		if (!y.mref[mn] || smodule_emitted(m))
			continue;
		buf_printf(&tops, "static const struct cbl_ymodule m%zu = {\n"
		    "\t.schema = &%s_schema,\n\t.name = ", mn, nm.p + 1);
		cstr(&tops, m->name);
		buf_puts(&tops, ",\n\t.revision = ");
		cstr(&tops, m->revision);
		buf_puts(&tops, ",\n\t.ns = ");
		cstr(&tops, m->ns);
		buf_puts(&tops, ",\n\t.prefix = ");
		cstr(&tops, m->prefix);
		buf_printf(&tops, ",\n\t.sid = UINT64_C(%" PRIu64 "),\n};\n\n",
		    m->sid);
	}

	buf_init(&head);
	buf_printf(&head, "/*\n * Generated by cblink-gen %s from %s.  Do not "
	    "edit.\n *\n * The schema tables (cbl_schema.h):\n%s * in all, "
	    "%zu nodes (children found %zu dense, %zu by a table, %zu by a "
	    "search),\n * %zu types, %zu expressions, %zu identities, %zu "
	    "bytes\n */\n\n"
	    "#include <stdbool.h>\n#include <stddef.h>\n#include <stdint.h>\n\n"
	    "#include <string.h>\n\n#include <cbl_schema.h>\n\n"
	    "#include \"%s.h\"\n\n", CBLGEN_VERSION,
	    from,
	    sizes.p != NULL ? sizes.p : "", y.nnodes, y.ndense, y.nmapped,
	    y.nsearched, y.ntypes, y.nxp, nident, total, base);
	/* Said when the tables are good: the file's comment, its lines. */
	if (report != NULL && d->n == errs) {
		for (const char *p = sizes.p; p != NULL && *p != '\0';) {
			const char *e = strchr(p, '\n');

			fprintf(report, "%.*s\n", (int)(e - p - 3), p + 3);
			p = e + 1;
		}
		fprintf(report, "in all: %zu nodes (children found %zu dense, "
		    "%zu by a table, %zu by a search), %zu types, %zu "
		    "expressions, %zu identities, %zu bytes\n", y.nnodes,
		    y.ndense, y.nmapped, y.nsearched, y.ntypes, y.nxp, nident,
		    total);
	}
	/* Declared first: they point at each other. */
	for (i = 0; i < s->nmods; i++)
		if (y.mref[i])
			buf_printf(&head, "static const struct cbl_ymodule m%zu;\n",
			    i);
	for (i = 0; i < y.nchoices; i++)
		buf_printf(&head, "static const struct cbl_ychoice c%zu;\n", i);
	for (i = 0; i < y.nnodes; i++)
		buf_printf(&head, "static const struct cbl_ynode n%zu;\n", i);
	buf_puts(out, head.p);
	buf_puts(out, "\n");
	if (y.types.len > 0)
		buf_puts(out, y.types.p);
	if (y.body.len > 0)
		buf_puts(out, y.body.p);
	if (idents.len > 0)
		buf_puts(out, idents.p);
	if (tops.len > 0)
		buf_puts(out, tops.p);
	buf_puts(out, "static const struct cbl_ymodule *const mods[] = {\n");
	for (i = 0, mn = 0; i < s->nmods; i++)
		if (smodule_emitted(s->mods[i])) {
			buf_printf(out, "\t&m%zu,\n", i);
			mn++;
		}
	buf_printf(out, "};\n\nstatic const struct cbl_ynode *const nodes[] = {"
	    "\n%s\n};\n", y.nall > 0 ? bysid.p : "\tNULL");
	/* Every annotation by SID: a SID is one annotation's. */
	qsort(annots, nall, sizeof(*annots), annot_by_sid);
	buf_puts(out, "\nstatic const struct cbl_yannot *const annots[] = {\n");
	for (i = 0; i < nall; i++) {
		if (i > 0 && annots[i].sid == annots[i - 1].sid)
			diag_add(d, 0, 0, "SID %" PRIu64 " is two annotations'",
			    annots[i].sid);
		buf_printf(out, "\t&m%zu_a[%zu],\n", annots[i].mn,
		    annots[i].i);
	}
	if (nall == 0)
		buf_puts(out, "\tNULL,\n");
	buf_puts(out, "};\n");
	buf_puts(out, "\nstatic const char *const xpaths[] = {\n");
	for (i = 0; i < y.nxp; i++) {
		buf_puts(out, "\t");
		cstr(out, y.xp[i]);
		buf_puts(out, ",\n");
	}
	if (y.nxp == 0)
		buf_puts(out, "\tNULL,\n");
	buf_printf(out, "};\n\nextern const struct cbl_yschema %s_schema;\n"
	    "const struct cbl_yschema %s_schema = {\n\t.nmod = %zu,\n"
	    "\t.nxpath = %zu,\n\t.nident = %zu,\n\t.nnode = %zu,\n"
	    "\t.mod = mods,\n\t.node = nodes,\n\t.xpath = xpaths,\n"
	    "\t.ident = idents,\n\t.nannot = %zu,\n\t.annot = annots,\n};\n",
	    nm.p + 1, nm.p + 1, mn, y.nxp, nident, y.nall, nall);
	if (y.codec.len > 0)
		buf_printf(out, "\n%s", y.codec.p);

	for (i = 0; i < y.ntypes; i++)
		free(y.tkeys[i]);
	free(y.tkeys);
	for (i = 0; i < y.nxp; i++)
		free(y.xp[i]);
	free(y.xp);
	for (size_t fcod = 0; fcod < y.ncodecs; fcod++)
		free(y.codecs[fcod]);
	free(y.codecs);
	free(y.mref);
	free(y.nodes.k);
	free(y.nodes.v);
	free(y.structs.k);
	free(y.structs.v);
	free(y.choices.k);
	free(y.choices.v);
	free(y.mods.k);
	free(y.mods.v);
	buf_free(&y.types);
	buf_free(&y.codec);
	buf_free(&y.body);
	buf_free(&tops);
	buf_free(&idents);
	buf_free(&bysid);
	free(y.all);
	free(annots);
	free(y.bases.k);
	free(y.bases.v);
	free(y.basev);
	buf_free(&sizes);
	buf_free(&head);
	buf_free(&nm);
	return (d->n > errs ? -1 : 0);
}
