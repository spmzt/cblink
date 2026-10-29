/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * YANG-CBOR (RFC 9254) to and from the C structs cblink-gen writes of
 * YANG modules, by their schema tables (cbl_schema.h): one codec for
 * every struct, the tables saying where each node is in it.
 *
 * A node's value is a map of its children, each keyed by the delta of
 * its SID from the node's (section 3.2); a list an array of such maps,
 * a leaf-list an array of values.  Values (section 6): integers as
 * themselves, decimal64 as tag 4 [exponent, mantissa], a string as text,
 * binary and bits as bytes, boolean, empty as null, an enumeration as
 * its value, an identityref as its SID, an instance-identifier and
 * anydata as the CBOR they are.  In a union, the members that would not
 * be told apart are tagged: bits 43, an enumeration 44 with its name,
 * an identityref 45, an instance-identifier 46.
 *
 * Decoding takes definite lengths only; a count is held against the
 * bytes there are before anything is allocated, as the rest of the
 * library does; what it makes is the arena's.  It checks what the CBOR
 * is, not what the schema further says (ranges, patterns, mandatory):
 * that is the validator's.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_data.h"
#include "cbl_dimpl.h"
#include "cbl_impl.h"
#include "cbl_schema.h"
#include "cbl_yimpl.h"

#define	YDEPTH_MAX	CBL_DEPTH_HARD_MAX
/*
 * draft-ietf-core-yang-metadata's tag of an annotated value, [metadata,
 * value]: provisional, IANA has not assigned it.
 */
#define	YTAG_META	109

/*
 * What one arena may hold, by default: a struct is allocated for as
 * little as one byte of input (an empty map, a list entry), so what a
 * frame asks for is bounded here, not by its length.
 */
#define	YARENA_LIMIT	(64 * 1024 * 1024)
#define	NOMEM		"no memory, or past the arena's limit"

/* What cbl_yarena_atfree() was given, the last first. */
struct yatfree {
	void		(*fn)(void *);
	void		 *arg;
	struct yatfree	 *next;
};

struct cbl_yarena {
	struct cbl_arena	 ar;
	size_t			 used;
	size_t			 limit;
	struct yatfree		*atfree;
};

cbl_yarena *
cbl_yarena_new(void)
{
	cbl_yarena *a;

	if ((a = calloc(1, sizeof(*a))) == NULL)
		return (NULL);
	cbl_arena_init(&a->ar);
	a->limit = YARENA_LIMIT;
	return (a);
}

void
cbl_yarena_free(cbl_yarena *a)
{
	struct yatfree *t;

	if (a == NULL)
		return;
	while ((t = a->atfree) != NULL) {
		a->atfree = t->next;
		t->fn(t->arg);
		free(t);
	}
	cbl_arena_free(&a->ar);
	free(a);
}

int
cbl_yarena_atfree(cbl_yarena *a, void (*fn)(void *), void *arg)
{
	struct yatfree *t;

	if (a == NULL || fn == NULL)
		return (EINVAL);
	if ((t = malloc(sizeof(*t))) == NULL)
		return (ENOMEM);
	t->fn = fn;
	t->arg = arg;
	t->next = a->atfree;
	a->atfree = t;
	return (0);
}

void
cbl_yarena_set_limit(cbl_yarena *a, size_t limit)
{

	if (a != NULL)
		a->limit = limit;
}

void *
cbl_yarena_alloc(cbl_yarena *a, size_t len)
{
	void *p;

	if (len == 0)
		len = 1;
	if (a == NULL || len > a->limit - a->used || a->used > a->limit)
		return (NULL);
	if ((p = cbl_arena_alloc(&a->ar, len)) != NULL) {
		memset(p, 0, len);
		a->used += len;
	}
	return (p);
}

void
cbl_ybuf_free(struct cbl_ybuf *b)
{

	free(b->p);
	memset(b, 0, sizeof(*b));
}

/*
 * Where a node is in its struct.
 */

/* A member's place: offsetof()'s, aligned as the member is. */
#define	AT(p, off)	((const void *)((const char *)(p) + (off)))
#define	WAT(p, off)	((void *)((char *)(p) + (off)))

/* A list or a leaf-list member: its count, then its array. */
struct yarr {
	size_t		 n;
	const void	*v;
};

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

/* Whether the case of every choice above n in struct p is n's. */
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

/* Whether child n has a value in struct p. */
static bool
present(const struct cbl_ynode *n, const void *p)
{
	const struct cbl_ytype *t = n->type;

	if (n->off == CBL_YOFF_NONE || !in_case(n, p))
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
	if (n->flags & CBL_YNF_KEY)
		return (true);
	switch (t->kind) {
	case CBL_YT_STRING:
		return (*(const char *const *)AT(p, n->off) != NULL);
	case CBL_YT_BINARY:
	case CBL_YT_BITS:
	case CBL_YT_INSTANCEID:
		return (((const struct cbl_bytes *)AT(p, n->off))->p != NULL);
	case CBL_YT_EMPTY:
		return (*(const bool *)AT(p, n->off));
	default:
		return (true);
	}
}

bool
cbl_ypresent(const struct cbl_ynode *n, const void *p)
{

	return (present(n, p));
}

/* n's case, and its choices', in struct p: EINVAL where another's is. */
static int
case_set(const struct cbl_ynode *n, void *p, const struct cbl_ychoice **bad)
{
	const struct cbl_ychoice *c = n->choice;
	uint32_t want = n->ccase;
	int had;

	for (; c != NULL; want = c->parent_case, c = c->parent) {
		if (c->off == CBL_YOFF_NONE)
			continue;
		had = read_enum(AT(p, c->off), sizeof(int));
		if (had != 0 && (uint32_t)had != want + 1) {
			*bad = c;
			return (EINVAL);
		}
		write_enum(WAT(p, c->off), sizeof(int), (int)want + 1);
	}
	return (0);
}

int
cbl_yset_case(const struct cbl_ynode *n, void *p)
{
	const struct cbl_ychoice *bad;

	return (case_set(n, p, &bad));
}

/*
 * Encoding.
 */

static int
put(struct cbl_ybuf *b, const void *d, size_t len)
{
	size_t cap;
	uint8_t *np;

	if (len > SIZE_MAX - b->len)
		return (ENOMEM);
	if (b->len + len > b->cap) {
		cap = b->cap == 0 ? 256 : b->cap;
		while (cap < b->len + len)
			cap *= 2;
		if ((np = realloc(b->p, cap)) == NULL)
			return (ENOMEM);
		b->p = np;
		b->cap = cap;
	}
	memcpy(b->p + b->len, d, len);
	b->len += len;
	return (0);
}

static int
put_head(struct cbl_ybuf *b, unsigned major, uint64_t v)
{
	uint8_t h[9];
	size_t n;

	if (v < 24) {
		h[0] = (uint8_t)(major << 5 | v);
		return (put(b, h, 1));
	}
	n = v <= UINT8_MAX ? 1 : v <= UINT16_MAX ? 2 : v <= UINT32_MAX ? 4 : 8;
	h[0] = (uint8_t)(major << 5 | (n == 1 ? 24 : n == 2 ? 25 : n == 4 ?
	    26 : 27));
	for (size_t i = 0; i < n; i++)
		h[n - i] = (uint8_t)(v >> (8 * i));
	return (put(b, h, n + 1));
}

static int
put_int(struct cbl_ybuf *b, int64_t v)
{

	return (v >= 0 ? put_head(b, 0, (uint64_t)v) :
	    put_head(b, 1, (uint64_t)(-1 - v)));
}

static int
put_simple(struct cbl_ybuf *b, uint8_t v)
{
	uint8_t h = (uint8_t)(7 << 5 | v);

	return (put(b, &h, 1));
}

static int	enc_map(struct cbl_ybuf *, const struct cbl_ynode *,
		    const void *, int);

/* The highest position a bits type has, and so how many bytes it needs. */
static size_t
bits_bytes(const struct cbl_ytype *t)
{
	int64_t max = -1;

	for (uint32_t i = 0; i < t->nitems; i++)
		if (t->items[i].value > max)
			max = t->items[i].value;
	return (max < 0 ? 0 : (size_t)(max / 8 + 1));
}

/*
 * Bits (RFC 9254 section 6.7): their bytes, bit n in byte n / 8, the
 * least significant first, with no trailing zero byte; in a union tag 43
 * and the names of those set, by position, a space between.
 */
static int
enc_bits(struct cbl_ybuf *b, const struct cbl_ytype *t,
    const struct cbl_bytes *by, bool inunion)
{
	const uint8_t *p = by->p;
	size_t len = by->len, tlen = 0;
	char *names;
	int error;

	while (len > 0 && p[len - 1] == 0)
		len--;
	if (!inunion) {
		if ((error = put_head(b, 2, len)) != 0)
			return (error);
		return (put(b, p, len));
	}
	for (uint32_t i = 0; i < t->nitems; i++)
		tlen += strlen(t->items[i].name) + 1;
	if ((names = calloc(1, tlen + 1)) == NULL)
		return (ENOMEM);
	/* By position: the items as written need not be in its order. */
	for (int64_t pos = 0; (size_t)pos < len * 8; pos++) {
		if ((p[pos / 8] & (1u << (pos % 8))) == 0)
			continue;
		for (uint32_t i = 0; i < t->nitems; i++)
			if (t->items[i].value == pos) {
				if (names[0] != '\0')
					strcat(names, " ");
				strcat(names, t->items[i].name);
				break;
			}
	}
	if ((error = put_head(b, 6, 43)) == 0 &&
	    (error = put_head(b, 3, strlen(names))) == 0)
		error = put(b, names, strlen(names));
	free(names);
	return (error);
}

static int
enc_value(struct cbl_ybuf *b, const struct cbl_ytype *t, const void *v,
    bool inunion)
{
	const struct cbl_bytes *by;
	const char *s;
	int e, error;

	switch (t->kind) {
	case CBL_YT_INT8:
		return (put_int(b, *(const int8_t *)v));
	case CBL_YT_INT16:
		return (put_int(b, *(const int16_t *)v));
	case CBL_YT_INT32:
		return (put_int(b, *(const int32_t *)v));
	case CBL_YT_INT64:
		return (put_int(b, *(const int64_t *)v));
	case CBL_YT_UINT8:
		return (put_head(b, 0, *(const uint8_t *)v));
	case CBL_YT_UINT16:
		return (put_head(b, 0, *(const uint16_t *)v));
	case CBL_YT_UINT32:
		return (put_head(b, 0, *(const uint32_t *)v));
	case CBL_YT_UINT64:
		return (put_head(b, 0, *(const uint64_t *)v));
	case CBL_YT_DECIMAL64:
		if ((error = put_head(b, 6, 4)) != 0 ||
		    (error = put_head(b, 4, 2)) != 0 ||
		    (error = put_int(b, -(int64_t)t->fdigits)) != 0)
			return (error);
		return (put_int(b, *(const int64_t *)v));
	case CBL_YT_BOOLEAN:
		return (put_simple(b, *(const bool *)v ? 21 : 20));
	case CBL_YT_EMPTY:
		return (put_simple(b, 22));
	case CBL_YT_STRING:
		s = *(const char *const *)v;
		if (s == NULL)
			s = "";
		if ((error = put_head(b, 3, strlen(s))) != 0)
			return (error);
		return (put(b, s, strlen(s)));
	case CBL_YT_BITS:
		return (enc_bits(b, t, v, inunion));
	case CBL_YT_BINARY:
		by = v;
		if ((error = put_head(b, 2, by->len)) != 0)
			return (error);
		return (put(b, by->p, by->len));
	case CBL_YT_ENUMERATION:
		e = read_enum(v, t->csize);
		if (!inunion)
			return (put_int(b, e));
		for (uint32_t i = 0; i < t->nitems; i++)
			if (t->items[i].value == e) {
				s = t->items[i].name;
				if ((error = put_head(b, 6, 44)) != 0 ||
				    (error = put_head(b, 3, strlen(s))) != 0)
					return (error);
				return (put(b, s, strlen(s)));
			}
		return (EINVAL);
	case CBL_YT_IDENTITYREF:
		if (inunion && (error = put_head(b, 6, 45)) != 0)
			return (error);
		return (put_head(b, 0, *(const uint64_t *)v));
	case CBL_YT_INSTANCEID:
		by = v;
		if (by->len == 0)
			return (EINVAL);
		if (inunion && (error = put_head(b, 6, 46)) != 0)
			return (error);
		return (put(b, by->p, by->len));
	case CBL_YT_UNION: {
		unsigned which = *(const unsigned *)v;

		if (which >= t->nmembers)
			return (EINVAL);
		return (enc_value(b, t->members[which], AT(v, t->voff), true));
	}
	}
	return (EINVAL);
}

static int
enc_child(struct cbl_ybuf *b, const struct cbl_ynode *n, const void *p,
    int depth)
{
	const struct yarr *a;
	const struct cbl_bytes *by;
	int error;

	switch (n->kind) {
	case CBL_YN_CONTAINER:
		return (enc_map(b, n, *(const void *const *)AT(p, n->off),
		    depth + 1));
	case CBL_YN_LIST:
		a = (const struct yarr *)AT(p, n->off);
		if ((error = put_head(b, 4, a->n)) != 0)
			return (error);
		for (size_t i = 0; i < a->n; i++)
			if ((error = enc_map(b, n, AT(a->v, i * n->size),
			    depth + 1)) != 0)
				return (error);
		return (0);
	case CBL_YN_LEAFLIST:
		a = (const struct yarr *)AT(p, n->off);
		if ((error = put_head(b, 4, a->n)) != 0)
			return (error);
		for (size_t i = 0; i < a->n; i++)
			if ((error = enc_value(b, n->type, AT(a->v, i *
			    n->type->csize), false)) != 0)
				return (error);
		return (0);
	case CBL_YN_LEAF:
		return (enc_value(b, n->type, AT(p, n->off), false));
	case CBL_YN_ANYDATA:
	case CBL_YN_ANYXML:
		by = (const struct cbl_bytes *)AT(p, n->off);
		return (put(b, by->p, by->len));
	}
	return (EINVAL);
}

/*
 * A mount point's mounted (CBL_YNF_MOUNT, RFC 8528): how many of the
 * mounted modules' top-level nodes are there; and those, each keyed by
 * its absolute SID, tag 47 (RFC 9254 section 4.2.1).
 */
static uint32_t
mounted_count(const struct cbl_ynode *n, const void *p)
{
	const struct cbl_ymounts *m;
	uint32_t k = 0;

	if ((n->flags & CBL_YNF_MOUNT) == 0 || p == NULL)
		return (0);
	m = (const struct cbl_ymounts *)AT(p, n->moff);
	for (size_t i = 0; i < m->n; i++)
		for (uint32_t j = 0; m->v[i].data != NULL &&
		    j < m->v[i].module->ntop; j++)
			k += present(m->v[i].module->top[j], m->v[i].data);
	return (k);
}

static int
enc_mounted(struct cbl_ybuf *b, const struct cbl_ynode *n, const void *p,
    int depth)
{
	const struct cbl_ymounts *m;
	int error;

	if ((n->flags & CBL_YNF_MOUNT) == 0)
		return (0);
	m = (const struct cbl_ymounts *)AT(p, n->moff);
	for (size_t i = 0; i < m->n; i++)
		for (uint32_t j = 0; m->v[i].data != NULL &&
		    j < m->v[i].module->ntop; j++) {
			const struct cbl_ynode *c = m->v[i].module->top[j];

			if (!present(c, m->v[i].data))
				continue;
			if ((error = put_head(b, 6, 47)) != 0 ||
			    (error = put_head(b, 0, c->sid)) != 0 ||
			    (error = enc_child(b, c, m->v[i].data, depth)) != 0)
				return (error);
		}
	return (0);
}

/* What may be mounted at mount point n: its schema's top-level data
 * node of SID sid; NULL, none. */
static const struct cbl_ynode *
mounted_node(const struct cbl_ynode *n, uint64_t sid)
{
	const struct cbl_ynode *c;

	c = cbl_yschema_node(n->module->schema, sid);
	if (c == NULL || c->parent != NULL || c->kind == CBL_YN_RPC ||
	    c->kind == CBL_YN_NOTIF || c->kind == CBL_YN_ACTION ||
	    c->off == CBL_YOFF_NONE)
		return (NULL);
	return (c);
}

void *
cbl_ymount_data(const struct cbl_ynode *n, void *p,
    const struct cbl_ymodule *mod, cbl_yarena *a)
{
	struct cbl_ymounts *m;
	struct cbl_ymounted *v;
	void *data;

	if (n == NULL || p == NULL || mod == NULL || a == NULL ||
	    (n->flags & CBL_YNF_MOUNT) == 0)
		return (NULL);
	m = (struct cbl_ymounts *)WAT(p, n->moff);
	for (size_t i = 0; i < m->n; i++)
		if (m->v[i].module == mod)
			return (m->v[i].data);
	if ((data = cbl_yarena_alloc(a, mod->size > 0 ? mod->size : 1)) ==
	    NULL || (v = cbl_yarena_alloc(a, (m->n + 1) * sizeof(*v))) == NULL)
		return (NULL);
	memset(data, 0, mod->size > 0 ? mod->size : 1);
	if (m->n > 0)
		memcpy(v, m->v, m->n * sizeof(*v));
	v[m->n].module = mod;
	v[m->n].data = data;
	m->v = v;
	m->n++;
	return (data);
}

const void *
cbl_ymount_find(const struct cbl_ynode *n, const void *p,
    const struct cbl_ymodule *mod)
{
	const struct cbl_ymounts *m;

	if (n == NULL || p == NULL || (n->flags & CBL_YNF_MOUNT) == 0)
		return (NULL);
	m = (const struct cbl_ymounts *)AT(p, n->moff);
	for (size_t i = 0; i < m->n; i++)
		if (m->v[i].module == mod)
			return (m->v[i].data);
	return (NULL);
}

/* n's children in struct p, a map keyed by their deltas from n. */
static int
enc_map(struct cbl_ybuf *b, const struct cbl_ynode *n, const void *p,
    int depth)
{
	uint32_t k = 0;
	int error;

	if (depth > YDEPTH_MAX)
		return (ELOOP);
	for (uint32_t i = 0; i < n->nchild; i++)
		k += present(n->child[i], p);
	k += mounted_count(n, p);
	if ((error = put_head(b, 5, k)) != 0)
		return (error);
	for (uint32_t i = 0; i < n->nchild; i++) {
		const struct cbl_ynode *c = n->child[i];

		if (!present(c, p))
			continue;
		if ((error = put_int(b, (int64_t)(c->sid -
		    cbl_ynode_base(n)))) != 0 ||
		    (error = enc_child(b, c, p, depth)) != 0)
			return (error);
	}
	return (enc_mounted(b, n, p, depth));
}

int
cbl_yencode(const struct cbl_ynode *n, const void *p, struct cbl_ybuf *b)
{

	if (n == NULL || p == NULL || b == NULL)
		return (EINVAL);
	return (enc_map(b, n, p, 0));
}

int
cbl_yencode_sid(const struct cbl_ynode *n, const void *p, struct cbl_ybuf *b)
{
	int error;

	if (n == NULL || p == NULL || b == NULL)
		return (EINVAL);
	/* Top-level keys are SIDs themselves (RFC 9254 section 3.2). */
	if ((error = put_head(b, 5, 1)) != 0 ||
	    (error = put_head(b, 0, n->sid)) != 0)
		return (error);
	return (enc_map(b, n, p, 0));
}

int
cbl_yencode_member(const struct cbl_ynode *n, const void *parent,
    struct cbl_ybuf *b)
{

	if (n == NULL || parent == NULL || b == NULL)
		return (EINVAL);
	if (!present(n, parent))
		return (ENOENT);
	return (enc_child(b, n, parent, 0));
}

bool
cbl_ymember_present(const struct cbl_ynode *n, const void *parent)
{

	return (n != NULL && parent != NULL && present(n, parent));
}

/*
 * Decoding.
 */

struct yrd {
	const uint8_t	*p, *end, *start;
	cbl_yarena	*a;
	int		 flags;
	char		*why;
	size_t		 whylen;
	const struct cbl_ymodule *leafmod;	/* an identityref's, by name */
};

static int	dec_bits(struct yrd *, const struct cbl_ytype *,
		    struct cbl_bytes *, bool);
static int	ident_named(struct yrd *, uint64_t *);

static int
fail(struct yrd *r, int error, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (r->why != NULL && r->whylen > 0 && r->why[0] == '\0') {
		n = snprintf(r->why, r->whylen, "at byte %td: ",
		    r->p - r->start);
		if (n > 0 && (size_t)n < r->whylen) {
			va_start(ap, fmt);
			(void)vsnprintf(r->why + n, r->whylen - (size_t)n, fmt,
			    ap);
			va_end(ap);
		}
	}
	return (error);
}

/* An item's head, not taken: its major type, additional info, length. */
static int
peek(struct yrd *r, unsigned *major, uint64_t *arg, size_t *hlen)
{
	unsigned ai;
	size_t n;

	if (r->p >= r->end)
		return (fail(r, EINVAL, "truncated"));
	*major = *r->p >> 5;
	ai = *r->p & 0x1f;
	if (ai < 24) {
		*arg = ai;
		*hlen = 1;
		return (0);
	}
	if (ai > 27)
		return (fail(r, EINVAL, ai == 31 ? "an indefinite length" :
		    "a reserved head"));
	n = (size_t)1 << (ai - 24);
	if ((size_t)(r->end - r->p) < n + 1)
		return (fail(r, EINVAL, "truncated"));
	*arg = 0;
	for (size_t i = 1; i <= n; i++)
		*arg = *arg << 8 | r->p[i];
	*hlen = n + 1;
	return (0);
}

static int
head(struct yrd *r, unsigned want, uint64_t *arg, const char *what)
{
	unsigned major;
	size_t hlen;
	int error;

	if ((error = peek(r, &major, arg, &hlen)) != 0)
		return (error);
	if (major != want)
		return (fail(r, EINVAL, "%s expected", what));
	r->p += hlen;
	return (0);
}

/* A count of items each of at least one byte: no more than there are. */
static int
count(struct yrd *r, uint64_t n, uint64_t per)
{

	if (n > (uint64_t)(r->end - r->p) / per)
		return (fail(r, EINVAL, "a count past the end"));
	return (0);
}

static int
skip(struct yrd *r, int depth)
{
	unsigned major;
	uint64_t arg;
	size_t hlen;
	int error;

	if (depth > YDEPTH_MAX)
		return (fail(r, ELOOP, "nested too deep"));
	if ((error = peek(r, &major, &arg, &hlen)) != 0)
		return (error);
	r->p += hlen;
	switch (major) {
	case 2:
	case 3:
		if (arg > (uint64_t)(r->end - r->p))
			return (fail(r, EINVAL, "truncated"));
		r->p += arg;
		return (0);
	case 4:
	case 5:
		if ((error = count(r, arg, major == 5 ? 2 : 1)) != 0)
			return (error);
		for (uint64_t i = 0; i < arg * (major == 5 ? 2 : 1); i++)
			if ((error = skip(r, depth + 1)) != 0)
				return (error);
		return (0);
	case 6:
		return (skip(r, depth + 1));
	default:
		return (0);
	}
}

/* From the arena, within its limit; NULL past it. */
static void *
ralloc(struct yrd *r, size_t len)
{

	return (cbl_yarena_alloc(r->a, len));
}

/* The next item as it is, copied: anydata, an instance-identifier. */
static int
raw(struct yrd *r, struct cbl_bytes *out)
{
	const uint8_t *from = r->p;
	void *copy;
	int error;

	if ((error = skip(r, 0)) != 0)
		return (error);
	if ((copy = ralloc(r, (size_t)(r->p - from))) == NULL)
		return (fail(r, ENOMEM, NOMEM));
	memcpy(copy, from, (size_t)(r->p - from));
	out->p = copy;
	out->len = (size_t)(r->p - from);
	return (0);
}

static int
dec_int(struct yrd *r, int64_t min, uint64_t max, bool sgn, uint64_t *u,
    int64_t *s)
{
	unsigned major;
	uint64_t arg;
	size_t hlen;
	int error;

	if ((error = peek(r, &major, &arg, &hlen)) != 0)
		return (error);
	if (major == 0) {
		if (arg > max)
			return (fail(r, ERANGE, "an integer out of range"));
		*u = arg;
		*s = (int64_t)arg;
	} else if (major == 1 && sgn) {
		if (arg > (uint64_t)(-(min + 1)))
			return (fail(r, ERANGE, "an integer out of range"));
		*s = -1 - (int64_t)arg;
	} else
		return (fail(r, EINVAL, "an integer expected"));
	r->p += hlen;
	return (0);
}

static bool	tag(struct yrd *, uint64_t);

/*
 * A map's key: a SID's delta, a bare integer; or an absolute SID in tag
 * 47 (RFC 9254 section 4.2.1), *abs and the SID in *u.
 */
static int
dec_key(struct yrd *r, bool *abs, uint64_t *u, int64_t *delta)
{

	*abs = tag(r, 47);
	if (*abs) {
		*delta = 0;
		return (dec_int(r, 0, UINT64_MAX, false, u, delta));
	}
	return (dec_int(r, INT64_MIN, INT64_MAX, true, u, delta));
}

static int
dec_text(struct yrd *r, const char **out, size_t *lenp)
{
	uint64_t len;
	char *s;
	int error;

	if ((error = head(r, 3, &len, "a text string")) != 0)
		return (error);
	if (len > (uint64_t)(r->end - r->p))
		return (fail(r, EINVAL, "truncated"));
	if (memchr(r->p, '\0', (size_t)len) != NULL)
		return (fail(r, EINVAL, "a NUL in a string"));
	/* YANG strings are Unicode (RFC 7950 section 9.4), sent as UTF-8. */
	if (!cbl_utf8_valid(r->p, (size_t)len))
		return (fail(r, EINVAL, "a string that is not UTF-8"));
	if ((s = ralloc(r, (size_t)len + 1)) == NULL)
		return (fail(r, ENOMEM, NOMEM));
	memcpy(s, r->p, (size_t)len);
	r->p += len;
	*out = s;
	if (lenp != NULL)
		*lenp = (size_t)len;
	return (0);
}

static int
dec_bytes(struct yrd *r, struct cbl_bytes *out)
{
	uint64_t len;
	void *d;
	int error;

	if ((error = head(r, 2, &len, "a byte string")) != 0)
		return (error);
	if (len > (uint64_t)(r->end - r->p))
		return (fail(r, EINVAL, "truncated"));
	if ((d = ralloc(r, (size_t)len)) == NULL)
		return (fail(r, ENOMEM, NOMEM));
	memcpy(d, r->p, (size_t)len);
	r->p += len;
	out->p = d;
	out->len = (size_t)len;
	return (0);
}

/* The tag before an item, if it is one: taken. */
static bool
tag(struct yrd *r, uint64_t want)
{
	unsigned major;
	uint64_t arg;
	size_t hlen;

	if (peek(r, &major, &arg, &hlen) != 0 || major != 6 || arg != want)
		return (false);
	r->p += hlen;
	return (true);
}

/*
 * Whether the enum named after a tag of hlen bytes is one of t's: of two
 * enumerations in a union, the one that has it.
 */
static bool
has_name(const struct yrd *r, size_t hlen, const struct cbl_ytype *t)
{
	struct yrd look = *r;
	unsigned major;
	uint64_t len;
	size_t nlen;

	look.why = NULL;
	look.p += hlen;
	if (peek(&look, &major, &len, &nlen) != 0 || major != 3 ||
	    len > (uint64_t)(look.end - look.p - nlen))
		return (false);
	look.p += nlen;
	for (uint32_t i = 0; i < t->nitems; i++)
		if (strlen(t->items[i].name) == len &&
		    memcmp(t->items[i].name, look.p, (size_t)len) == 0)
			return (true);
	return (false);
}

/*
 * Which member of union t, from the from'th, the next item may be, by
 * what it is: its tag, or its major type; -1 none.
 */
static int
member(struct yrd *r, const struct cbl_ytype *t, uint16_t from)
{
	unsigned major, kind;
	uint64_t arg;
	size_t hlen;

	if (peek(r, &major, &arg, &hlen) != 0)
		return (-1);
	for (uint16_t i = from; i < t->nmembers; i++) {
		kind = t->members[i]->kind;
		if (major == 6) {
			if (arg == 44 && kind == CBL_YT_ENUMERATION) {
				if (has_name(r, hlen, t->members[i]))
					return (i);
			} else if ((arg == 43 && kind == CBL_YT_BITS) ||
			    (arg == 45 && kind == CBL_YT_IDENTITYREF) ||
			    (arg == 46 && kind == CBL_YT_INSTANCEID) ||
			    (arg == 4 && kind == CBL_YT_DECIMAL64))
				return (i);
		} else if (major == 0 || major == 1) {
			/* The first integer it fits. */
			struct yrd try = *r;
			uint64_t u;
			int64_t s;
			bool sgn = kind >= CBL_YT_INT8 && kind <= CBL_YT_INT64;
			static const int64_t smin[] = { INT8_MIN, INT16_MIN,
			    INT32_MIN, INT64_MIN };
			static const uint64_t smax[] = { INT8_MAX, INT16_MAX,
			    INT32_MAX, INT64_MAX };
			static const uint64_t umax[] = { UINT8_MAX, UINT16_MAX,
			    UINT32_MAX, UINT64_MAX };

			try.why = NULL;
			if (sgn && dec_int(&try, smin[kind - CBL_YT_INT8],
			    smax[kind - CBL_YT_INT8], true, &u, &s) == 0)
				return (i);
			if (kind >= CBL_YT_UINT8 && kind <= CBL_YT_UINT64 &&
			    dec_int(&try, 0, umax[kind - CBL_YT_UINT8], false,
			    &u, &s) == 0)
				return (i);
		} else if ((major == 3 && kind == CBL_YT_STRING) ||
		    (major == 2 && kind == CBL_YT_BINARY) ||
		    (major == 7 && (arg == 20 || arg == 21) &&
		    kind == CBL_YT_BOOLEAN) ||
		    (major == 7 && arg == 22 && kind == CBL_YT_EMPTY))
			return (i);
		if (kind == CBL_YT_UNION && member(r, t->members[i], 0) >= 0)
			return (i);
	}
	return (-1);
}

static int
dec_value(struct yrd *r, const struct cbl_ytype *t, void *v, bool inunion)
{
	static const int64_t smin[] = { INT8_MIN, INT16_MIN, INT32_MIN,
	    INT64_MIN };
	static const uint64_t smax[] = { INT8_MAX, INT16_MAX, INT32_MAX,
	    INT64_MAX };
	static const uint64_t umax[] = { UINT8_MAX, UINT16_MAX, UINT32_MAX,
	    UINT64_MAX };
	unsigned major;
	uint64_t arg, u;
	int64_t s;
	size_t hlen, len;
	const char *name;
	int m, error;

	switch (t->kind) {
	case CBL_YT_INT8:
	case CBL_YT_INT16:
	case CBL_YT_INT32:
	case CBL_YT_INT64:
		if ((error = dec_int(r, smin[t->kind - CBL_YT_INT8],
		    smax[t->kind - CBL_YT_INT8], true, &u, &s)) != 0)
			return (error);
		if (t->kind == CBL_YT_INT8)
			*(int8_t *)v = (int8_t)s;
		else if (t->kind == CBL_YT_INT16)
			*(int16_t *)v = (int16_t)s;
		else if (t->kind == CBL_YT_INT32)
			*(int32_t *)v = (int32_t)s;
		else
			*(int64_t *)v = s;
		return (0);
	case CBL_YT_UINT8:
	case CBL_YT_UINT16:
	case CBL_YT_UINT32:
	case CBL_YT_UINT64:
		if ((error = dec_int(r, 0, umax[t->kind - CBL_YT_UINT8], false,
		    &u, &s)) != 0)
			return (error);
		if (t->kind == CBL_YT_UINT8)
			*(uint8_t *)v = (uint8_t)u;
		else if (t->kind == CBL_YT_UINT16)
			*(uint16_t *)v = (uint16_t)u;
		else if (t->kind == CBL_YT_UINT32)
			*(uint32_t *)v = (uint32_t)u;
		else
			*(uint64_t *)v = u;
		return (0);
	case CBL_YT_DECIMAL64:
		if (!tag(r, 4))
			return (fail(r, EINVAL, "a decimal64 (tag 4) "
			    "expected"));
		if ((error = head(r, 4, &arg, "[exponent, mantissa]")) != 0)
			return (error);
		if (arg != 2)
			return (fail(r, EINVAL, "[exponent, mantissa] "
			    "expected"));
		if ((error = dec_int(r, INT64_MIN, INT64_MAX, true, &u,
		    &s)) != 0)
			return (error);
		if (s != -(int64_t)t->fdigits)
			return (fail(r, EINVAL, "a decimal64 of %u fraction "
			    "digits expected", t->fdigits));
		if ((error = dec_int(r, INT64_MIN, INT64_MAX, true, &u,
		    &s)) != 0)
			return (error);
		*(int64_t *)v = s;
		return (0);
	case CBL_YT_BOOLEAN:
	case CBL_YT_EMPTY:
		if ((error = peek(r, &major, &arg, &hlen)) != 0)
			return (error);
		if (major != 7 || (t->kind == CBL_YT_BOOLEAN ? arg != 20 &&
		    arg != 21 : arg != 22))
			return (fail(r, EINVAL, t->kind == CBL_YT_BOOLEAN ?
			    "true or false expected" : "null expected"));
		r->p += hlen;
		*(bool *)v = t->kind == CBL_YT_EMPTY || arg == 21;
		return (0);
	case CBL_YT_STRING:
		return (dec_text(r, (const char **)v, NULL));
	case CBL_YT_BITS:
		return (dec_bits(r, t, v, inunion));
	case CBL_YT_BINARY:
		return (dec_bytes(r, v));
	case CBL_YT_ENUMERATION:
		if (inunion) {
			if (!tag(r, 44))
				return (fail(r, EINVAL, "an enumeration (tag "
				    "44) expected"));
			if ((error = dec_text(r, &name, &len)) != 0)
				return (error);
			for (uint32_t i = 0; i < t->nitems; i++)
				if (strcmp(t->items[i].name, name) == 0) {
					write_enum(v, t->csize,
					    (int)t->items[i].value);
					return (0);
				}
			return (fail(r, EINVAL, "no enum %s", name));
		}
		if ((error = dec_int(r, INT32_MIN, INT32_MAX, true, &u, &s)) !=
		    0)
			return (error);
		for (uint32_t i = 0; i < t->nitems; i++)
			if (t->items[i].value == s) {
				write_enum(v, t->csize, (int)s);
				return (0);
			}
		return (fail(r, EINVAL, "no enum of value %jd", (intmax_t)s));
	case CBL_YT_IDENTITYREF:
		if (inunion && !tag(r, 45))
			return (fail(r, EINVAL, "an identityref (tag 45) "
			    "expected"));
		/* By SID, or by name (RFC 9254 section 6.10). */
		if ((error = peek(r, &major, &arg, &hlen)) != 0)
			return (error);
		if (major == 3)
			return (ident_named(r, (uint64_t *)v));
		if ((error = dec_int(r, 0, UINT64_MAX, false, &u, &s)) != 0)
			return (error);
		*(uint64_t *)v = u;
		return (0);
	case CBL_YT_INSTANCEID:
		if (inunion && !tag(r, 46))
			return (fail(r, EINVAL, "an instance-identifier (tag "
			    "46) expected"));
		return (raw(r, v));
	case CBL_YT_UNION: {
		/*
		 * The first member it is a value of, restrictions and all
		 * (RFC 7950 9.12): two strings, one of a pattern, are told
		 * apart by it.  The last that may be is taken as it is, for
		 * the validator to say why not.
		 */
		const struct yrd at = *r;
		int next;

		if ((m = member(r, t, 0)) < 0)
			return (fail(r, EINVAL, "no member of the union is "
			    "this"));
		for (;; m = next) {
			*r = at;
			memset(WAT(v, t->voff), 0, t->csize - t->voff);
			*(unsigned *)v = (unsigned)m;
			next = member(r, t, (uint16_t)(m + 1));
			if ((error = dec_value(r, t->members[m], WAT(v,
			    t->voff), true)) != 0 && next < 0)
				return (error);
			if (next < 0 || (error == 0 && cbl_ytype_admits(
			    r->leafmod != NULL ? r->leafmod->schema : NULL,
			    t->members[m], AT(v, t->voff))))
				return (error);
			if (r->why != NULL && r->whylen > 0)
				r->why[0] = '\0';
		}
	}
	}
	return (fail(r, EINVAL, "a type not known"));
}

static int	dec_map(struct yrd *, const struct cbl_ynode *, void *, int);

/* A set bit, its byte grown to in a buffer of len bytes. */
static void
set_bit(uint8_t *p, int64_t pos)
{

	p[pos / 8] |= (uint8_t)(1u << (pos % 8));
}

/*
 * Bits read: their bytes, or the sparse array of byte strings that do not
 * end in a zero byte and counts of zero bytes between, alternating, two
 * elements at least; or in a union tag 43 and names.  No more bytes than
 * the type's highest position needs: what a count asks is bounded.
 */
static int
dec_bits(struct yrd *r, const struct cbl_ytype *t, struct cbl_bytes *out,
    bool inunion)
{
	struct yrd look;
	unsigned major, prev;
	uint64_t arg, k, total = 0;
	size_t hlen, max = bits_bytes(t), len, at;
	const char *names, *w, *e;
	uint8_t *p;
	int error;

	if (inunion) {
		if (!tag(r, 43))
			return (fail(r, EINVAL, "bits (tag 43) expected"));
		if ((error = dec_text(r, &names, &len)) != 0)
			return (error);
		if ((p = ralloc(r, max)) == NULL)
			return (fail(r, ENOMEM, NOMEM));
		for (w = names; *w != '\0'; w = *e == ' ' ? e + 1 : e) {
			uint32_t i;

			e = strchr(w, ' ') != NULL ? strchr(w, ' ') : w +
			    strlen(w);
			for (i = 0; i < t->nitems; i++)
				if (strlen(t->items[i].name) == (size_t)(e - w) &&
				    memcmp(t->items[i].name, w, (size_t)(e - w))
				    == 0)
					break;
			if (i == t->nitems)
				return (fail(r, EINVAL, "no bit %.*s",
				    (int)(e - w), w));
			set_bit(p, t->items[i].value);
		}
		while (max > 0 && p[max - 1] == 0)
			max--;
		out->p = p;
		out->len = max;
		return (0);
	}
	if ((error = peek(r, &major, &arg, &hlen)) != 0)
		return (error);
	if (major == 2) {
		if ((error = dec_bytes(r, out)) != 0)
			return (error);
		/* A receiver may take trailing zero bytes: dropped. */
		while (out->len > 0 &&
		    ((const uint8_t *)out->p)[out->len - 1] == 0)
			out->len--;
		return (0);
	}
	if (major != 4)
		return (fail(r, EINVAL, "bits expected"));
	/* The array: checked and measured, then copied. */
	look = *r;
	look.why = NULL;
	(void)head(&look, 4, &k, "an array");
	if (k < 2)
		return (fail(r, EINVAL, "bits as an array of one: sent bare"));
	if ((error = count(r, k, 1)) != 0)
		return (error);
	prev = 7;
	for (uint64_t i = 0; i < k; i++) {
		if (peek(&look, &major, &arg, &hlen) != 0 ||
		    (major != 0 && major != 2) || major == prev)
			return (fail(r, EINVAL, "bits: byte strings and counts "
			    "alternate"));
		look.p += hlen;
		if (major == 2) {
			if (arg == 0 || arg > (uint64_t)(look.end - look.p) ||
			    look.p[arg - 1] == 0)
				return (fail(r, EINVAL, "bits: a byte string "
				    "ends in a zero byte"));
			look.p += arg;
		}
		prev = major;
		if (arg > max || total > max - arg)
			return (fail(r, EINVAL, "bits past the type's "
			    "highest position"));
		total += arg;
	}
	if ((p = ralloc(r, (size_t)total)) == NULL)
		return (fail(r, ENOMEM, NOMEM));
	(void)head(r, 4, &k, "an array");
	for (at = 0; k > 0; k--) {
		(void)peek(r, &major, &arg, &hlen);
		r->p += hlen;
		if (major == 2) {
			memcpy(p + at, r->p, (size_t)arg);
			r->p += arg;
		}
		at += (size_t)arg;
	}
	len = (size_t)total;
	while (len > 0 && p[len - 1] == 0)
		len--;
	out->p = p;
	out->len = len;
	return (0);
}

/* An identityref by name: module:identity, or the leaf's module's. */
static int
ident_named(struct yrd *r, uint64_t *sid)
{
	const struct cbl_yschema *s;
	const char *name, *colon, *mod;
	size_t len, mlen;
	int error;

	if ((error = dec_text(r, &name, &len)) != 0)
		return (error);
	if (r->leafmod == NULL || (s = r->leafmod->schema) == NULL)
		return (fail(r, EINVAL, "an identity by name, no schema to "
		    "know it by"));
	if ((colon = strchr(name, ':')) != NULL) {
		mod = name;
		mlen = (size_t)(colon - name);
		name = colon + 1;
	} else {
		mod = r->leafmod->name;
		mlen = strlen(mod);
	}
	for (uint32_t i = 0; i < s->nident; i++)
		if (strcmp(s->ident[i].name, name) == 0 &&
		    strlen(s->ident[i].module->name) == mlen &&
		    memcmp(s->ident[i].module->name, mod, mlen) == 0) {
			*sid = s->ident[i].sid;
			return (0);
		}
	return (fail(r, EINVAL, "no identity %.*s:%s", (int)mlen, mod,
	    name));
}

/* Child n's value into struct p. */
/*
 * An annotated value's metadata passed over: the structs have no place
 * for it, and a reader may drop it (draft-ietf-core-yang-metadata).
 */
static int
unmeta(struct yrd *r, int depth)
{
	uint64_t k;
	int error;

	if (!tag(r, YTAG_META))
		return (0);
	if ((error = head(r, 4, &k, "an annotated value")) != 0)
		return (error);
	if (k != 2)
		return (fail(r, EINVAL, "an annotated value of %ju items, not "
		    "2", (uintmax_t)k));
	return (skip(r, depth));
}

static int
dec_child(struct yrd *r, const struct cbl_ynode *n, void *p, int depth)
{
	struct yarr *a;
	uint64_t k;
	void *q;
	int error;

	/* A list's or leaf-list's entries are annotated, not it. */
	if (n->kind != CBL_YN_LIST && n->kind != CBL_YN_LEAFLIST &&
	    (error = unmeta(r, depth)) != 0)
		return (error);
	switch (n->kind) {
	case CBL_YN_CONTAINER:
		if ((q = ralloc(r, n->size)) == NULL)
			return (fail(r, ENOMEM, NOMEM));
		*(void **)WAT(p, n->off) = q;
		return (dec_map(r, n, q, depth + 1));
	case CBL_YN_LIST:
	case CBL_YN_LEAFLIST:
		if ((error = head(r, 4, &k, "an array")) != 0 ||
		    (error = count(r, k, 1)) != 0)
			return (error);
		if (k > SIZE_MAX / (n->kind == CBL_YN_LIST ? n->size :
		    n->type->csize) || (q = ralloc(r, (size_t)k *
		    (n->kind == CBL_YN_LIST ? n->size : n->type->csize))) ==
		    NULL)
			return (fail(r, ENOMEM, NOMEM));
		a = (struct yarr *)WAT(p, n->off);
		a->n = (size_t)k;
		a->v = q;
		r->leafmod = n->module;
		for (uint64_t i = 0; i < k; i++) {
			if ((error = unmeta(r, depth)) != 0)
				return (error);
			error = n->kind == CBL_YN_LIST ? dec_map(r, n,
			    WAT(q, i * n->size), depth + 1) : dec_value(r,
			    n->type, WAT(q, i * n->type->csize), false);
			if (error != 0)
				return (error);
		}
		return (0);
	case CBL_YN_LEAF:
		r->leafmod = n->module;
		if ((error = dec_value(r, n->type, WAT(p, n->off), false)) != 0)
			return (error);
		if (n->hoff != CBL_YOFF_NONE)
			*(bool *)WAT(p, n->hoff) = true;
		return (0);
	case CBL_YN_ANYDATA:
	case CBL_YN_ANYXML:
		return (raw(r, (struct cbl_bytes *)WAT(p, n->off)));
	}
	return (fail(r, EINVAL, "%s: not a value", n->name));
}

/* Its case, and those of the choices above: another's is an error. */
static int
set_case(struct yrd *r, const struct cbl_ynode *n, void *p)
{
	const struct cbl_ychoice *bad;

	if (case_set(n, p, &bad) != 0)
		return (fail(r, EINVAL, "%s: two cases of choice %s",
		    n->name, bad->name));
	return (0);
}

static int
dec_map(struct yrd *r, const struct cbl_ynode *n, void *p, int depth)
{
	const struct cbl_ynode *c;
	uint64_t k, u;
	int64_t delta;
	uint8_t *seen;
	int error = 0;

	if (depth > YDEPTH_MAX)
		return (fail(r, ELOOP, "nested too deep"));
	if ((error = head(r, 5, &k, "a map")) != 0 ||
	    (error = count(r, k, 2)) != 0)
		return (error);
	if ((seen = calloc(n->nchild + 1, 1)) == NULL)
		return (fail(r, ENOMEM, NOMEM));
	for (uint64_t i = 0; i < k && error == 0; i++) {
		bool abs;

		if ((error = dec_key(r, &abs, &u, &delta)) != 0)
			break;
		/* Mounted (RFC 8528): a module's top-level node, by SID. */
		if (abs && (n->flags & CBL_YNF_MOUNT) != 0) {
			void *data;

			if ((c = mounted_node(n, u)) == NULL) {
				if (r->flags & CBL_YD_STRICT)
					error = fail(r, ENOENT, "%s: nothing "
					    "mounted is SID %ju", n->name,
					    (uintmax_t)u);
				else
					error = skip(r, depth);
				continue;
			}
			if ((data = cbl_ymount_data(n, p, c->module,
			    r->a)) == NULL)
				error = fail(r, ENOMEM, NOMEM);
			else
				error = dec_child(r, c, data, depth);
			continue;
		}
		c = abs ? cbl_ynode_child(n, (int64_t)(u -
		    cbl_ynode_base(n))) : cbl_ynode_child(n, delta);
		if (c == NULL || c->off == CBL_YOFF_NONE) {
			if (r->flags & CBL_YD_STRICT)
				error = fail(r, ENOENT, "%s: no child at delta "
				    "%jd", n->name, (intmax_t)delta);
			else
				error = skip(r, depth);
			continue;
		}
		/* Its place among the children, for twice. */
		for (u = 0; u < n->nchild && n->child[u] != c; u++)
			;
		if (seen[u]++) {
			error = fail(r, EINVAL, "%s: twice", c->name);
			break;
		}
		if ((error = set_case(r, c, p)) == 0)
			error = dec_child(r, c, p, depth);
	}
	free(seen);
	return (error);
}

int
cbl_ydecode(const struct cbl_ynode *n, const void *data, size_t len,
    void *p, cbl_yarena *a, int flags, char *why, size_t whylen)
{
	struct yrd r = { data, (const uint8_t *)data + len, data, a, flags,
	    why, whylen, NULL };
	int error;

	if (why != NULL && whylen > 0)
		why[0] = '\0';
	if (n == NULL || data == NULL || p == NULL || a == NULL)
		return (EINVAL);
	/* Zeroed as said: what the value leaves out is not there. */
	memset(p, 0, n->size);
	if ((error = unmeta(&r, 0)) != 0 || (error = dec_map(&r, n, p, 0)) != 0)
		return (error);
	if (r.p != r.end)
		return (fail(&r, EINVAL, "bytes after the value"));
	return (0);
}

/*
 * One value of leaf or leaf-list n, the CBOR item at data, into out as
 * its member is; a value of type t written; a head of major type major
 * (cbl_yimpl.h).
 */
int
cbl_ydecode_value(const struct cbl_ynode *n, const void *data, size_t len,
    void *out, cbl_yarena *a, char *why, size_t whylen)
{
	struct yrd r = { data, (const uint8_t *)data + len, data, a, 0,
	    why, whylen, NULL };
	int error;

	if (why != NULL && whylen > 0)
		why[0] = '\0';
	if (n == NULL || n->type == NULL || data == NULL || out == NULL ||
	    a == NULL)
		return (EINVAL);
	r.leafmod = n->module;
	if ((error = dec_value(&r, n->type, out, false)) != 0)
		return (error);
	if (r.p != r.end)
		return (fail(&r, EINVAL, "bytes after the value"));
	return (0);
}

int
cbl_yencode_value(struct cbl_ybuf *b, const struct cbl_ytype *t,
    const void *v)
{

	return (enc_value(b, t, v, false));
}

int
cbl_ycbor_head(struct cbl_ybuf *b, unsigned major, uint64_t v)
{

	return (put_head(b, major, v));
}

/* The length of the CBOR item at p, 0 where it is none. */
size_t
cbl_ycbor_skip(const uint8_t *p, const uint8_t *end)
{
	struct yrd r = { p, end, p, NULL, 0, NULL, 0, NULL };

	if (skip(&r, 0) != 0)
		return (0);
	return ((size_t)(r.p - p));
}

int
cbl_ydecode_member(const struct cbl_ynode *n, const void *data, size_t len,
    void *parent, cbl_yarena *a, int flags, char *why, size_t whylen)
{
	struct yrd r = { data, (const uint8_t *)data + len, data, a, flags,
	    why, whylen, NULL };
	int error;

	if (why != NULL && whylen > 0)
		why[0] = '\0';
	if (n == NULL || data == NULL || parent == NULL || a == NULL)
		return (EINVAL);
	if ((error = dec_child(&r, n, parent, 0)) != 0)
		return (error);
	if (r.p != r.end)
		return (fail(&r, EINVAL, "bytes after the value"));
	return (0);
}

/*
 * cbl_yiid_read()'s other way: n's instance-identifier, the SID alone or
 * [SID, values...], the keys of the lists from the top down to it, then
 * a leaf-list entry's value, each pointing at a value as its member is.
 */
int
cbl_yiid_write(const struct cbl_ynode *n, const void *const *vals,
    size_t nvals, struct cbl_ybuf *b)
{
	const struct cbl_ynode *chain[YDEPTH_MAX + 1], *x, *c;
	size_t nc = 0, need = 0, j = 0;
	int error;

	if (n == NULL || b == NULL || (nvals > 0 && vals == NULL))
		return (EINVAL);
	for (x = n; x != NULL; x = x->parent) {
		if (nc == sizeof(chain) / sizeof(chain[0]))
			return (ELOOP);
		chain[nc++] = x;
		if (x->kind == CBL_YN_LIST)
			need += x->nkeys;
	}
	if (n->kind == CBL_YN_LEAFLIST)
		need++;
	if (nvals != need)
		return (EINVAL);
	if (need == 0)
		return (put_head(b, 0, n->sid));
	if ((error = put_head(b, 4, 1 + need)) != 0 ||
	    (error = put_head(b, 0, n->sid)) != 0)
		return (error);
	while (nc-- > 0) {
		x = chain[nc];
		if (x->kind != CBL_YN_LIST)
			continue;
		for (uint16_t k = 0; k < x->nkeys; k++) {
			c = x->child[x->keys[k]];
			if ((error = enc_value(b, c->type, vals[j++], false)) !=
			    0)
				return (error);
		}
	}
	if (n->kind == CBL_YN_LEAFLIST)
		error = enc_value(b, n->type, vals[j], false);
	return (error);
}

int
cbl_yiid_read(const struct cbl_yschema *s, const struct cbl_bytes *v,
    const struct cbl_ynode **node, const void ***vals, size_t *nvals,
    cbl_yarena *a)
{
	struct yrd r = { v->p, (const uint8_t *)v->p + v->len, v->p, a, 0,
	    NULL, 0, NULL };
	const struct cbl_ynode *n, *chain[YDEPTH_MAX + 1];
	const void **out;
	uint64_t arg, sid, k = 1;
	unsigned major;
	size_t hlen, nc = 0, need = 0, j = 0;
	int64_t ignored;
	int error;

	if (s == NULL || v == NULL || v->p == NULL || v->len == 0)
		return (EINVAL);
	if ((error = peek(&r, &major, &arg, &hlen)) != 0)
		return (error);
	/* [SID, values...], or the SID alone. */
	if (major == 4) {
		if (arg < 2)
			return (EINVAL);
		r.p += hlen;
		k = arg;
	}
	if ((error = dec_int(&r, 0, UINT64_MAX, false, &sid, &ignored)) != 0)
		return (error);
	if ((n = cbl_yschema_node(s, sid)) == NULL)
		return (ENOENT);
	/* The lists from the top down, and how many values they take. */
	for (const struct cbl_ynode *x = n; x != NULL; x = x->parent) {
		if (nc == sizeof(chain) / sizeof(chain[0]))
			return (ELOOP);
		chain[nc++] = x;
		if (x->kind == CBL_YN_LIST)
			need += x->nkeys;
	}
	if (n->kind == CBL_YN_LEAFLIST)
		need++;
	if (k - 1 != need)
		return (EINVAL);
	if ((out = cbl_yarena_alloc(a, (need + 1) * sizeof(*out))) == NULL)
		return (ENOMEM);
	while (nc-- > 0) {
		const struct cbl_ynode *x = chain[nc];

		for (uint16_t i = 0; x->kind == CBL_YN_LIST && i < x->nkeys;
		    i++) {
			const struct cbl_ytype *t = x->child[x->keys[i]]->type;
			void *val;

			if ((val = cbl_yarena_alloc(a, t->csize)) == NULL)
				return (ENOMEM);
			if ((error = dec_value(&r, t, val, false)) != 0)
				return (error);
			out[j++] = val;
		}
	}
	if (n->kind == CBL_YN_LEAFLIST) {
		void *val;

		if ((val = cbl_yarena_alloc(a, n->type->csize)) == NULL)
			return (ENOMEM);
		if ((error = dec_value(&r, n->type, val, false)) != 0)
			return (error);
		out[j++] = val;
	}
	if (r.p != r.end)
		return (EINVAL);
	*node = n;
	*vals = out;
	*nvals = j;
	return (0);
}

/*
 * The instance tree's YANG-CBOR (cbl_data.h): what the structs' is, from
 * the nodes, with their annotations, written and read as
 * draft-ietf-core-yang-metadata has them: tag 109 of [metadata, value],
 * the metadata a map keyed by each annotation's delta from the node's own
 * SID (an entry's: its list's), its value as a leaf of its type would be.
 */

static int	enc_tmap(struct cbl_ybuf *, const cbl_dnode *, int);

static int
enc_meta(struct cbl_ybuf *b, const cbl_dnode *x)
{
	const struct cbl_dmeta *m;
	uint64_t k = 0;
	int error;

	for (m = x->meta; m != NULL; m = m->next)
		k++;
	if ((error = put_head(b, 6, YTAG_META)) != 0 ||
	    (error = put_head(b, 4, 2)) != 0 ||
	    (error = put_head(b, 5, k)) != 0)
		return (error);
	for (m = x->meta; m != NULL; m = m->next)
		if ((error = put_int(b, (int64_t)(m->an->sid -
		    x->sn->sid))) != 0 ||
		    (error = enc_value(b, m->an->type, m->value, false)) != 0)
			return (error);
	return (0);
}

/* x's instance: its value, in its annotations if it has them. */
static int
enc_tnode(struct cbl_ybuf *b, const cbl_dnode *x, int depth)
{
	const struct cbl_bytes *by;
	int error;

	if (x->meta != NULL && (error = enc_meta(b, x)) != 0)
		return (error);
	switch (x->sn->kind) {
	case CBL_YN_LEAF:
	case CBL_YN_LEAFLIST:
		return (enc_value(b, x->sn->type, x->value, false));
	case CBL_YN_ANYDATA:
	case CBL_YN_ANYXML:
		by = x->value;
		return (put(b, by->p, by->len));
	default:
		return (enc_tmap(b, x, depth + 1));
	}
}

/* x's children, keyed by their deltas from it; the root's by SID. */
static int
enc_tmap(struct cbl_ybuf *b, const cbl_dnode *x, int depth)
{
	const struct cbl_ynode *const *k;
	uint64_t base;
	uint32_t nk, n = 0;
	int error;

	if (depth > YDEPTH_MAX)
		return (ELOOP);
	if (x->sn == NULL || (x->sn->flags & CBL_YNF_MOUNT) != 0) {
		/* A mount point's: by absolute SID, tag 47. */
		k = x->tree->tops;
		nk = x->tree->ntops;
		base = 0;
	} else {
		k = x->sn->child;
		nk = x->sn->nchild;
		base = cbl_ynode_base(x->sn);
	}
	for (uint32_t i = 0; x->head != NULL && i < nk; i++)
		n += x->head[i] != NULL;
	if ((error = put_head(b, 5, n)) != 0)
		return (error);
	for (uint32_t i = 0; x->head != NULL && i < nk; i++) {
		const cbl_dnode *c = x->head[i], *y;
		uint64_t cnt = 0;

		if (c == NULL)
			continue;
		if (x->sn != NULL && (x->sn->flags & CBL_YNF_MOUNT) != 0 &&
		    (error = put_head(b, 6, 47)) != 0)
			return (error);
		if ((error = put_int(b, (int64_t)(k[i]->sid - base))) != 0)
			return (error);
		if (k[i]->kind != CBL_YN_LIST && k[i]->kind != CBL_YN_LEAFLIST) {
			if ((error = enc_tnode(b, c, depth)) != 0)
				return (error);
			continue;
		}
		for (y = c; y != NULL; y = y->next) {
			cnt++;
			if (y == x->tail[i])
				break;
		}
		if ((error = put_head(b, 4, cnt)) != 0)
			return (error);
		for (y = c; cnt > 0; y = y->next, cnt--)
			if ((error = enc_tnode(b, y, depth)) != 0)
				return (error);
	}
	return (0);
}

int
cbl_d_encode(const cbl_dnode *n, struct cbl_ybuf *b)
{

	if (n == NULL || b == NULL)
		return (EINVAL);
	return (n->sn == NULL ? enc_tmap(b, n, 0) : enc_tnode(b, n, 0));
}

/* An annotation read, to be put on its node once it is made. */
struct ymeta {
	const struct cbl_yannot	*an;
	void			*v;
};

/* A value's annotations, if it is in them; of node sn's. */
static int
dec_meta(struct yrd *r, const struct cbl_ynode *sn, struct ymeta **mv,
    size_t *nm, int depth)
{
	const struct cbl_yannot *an;
	uint64_t k, u;
	int64_t delta;
	int error;

	*mv = NULL;
	*nm = 0;
	if (!tag(r, YTAG_META))
		return (0);
	if ((error = head(r, 4, &k, "an annotated value")) != 0)
		return (error);
	if (k != 2)
		return (fail(r, EINVAL, "%s: an annotated value of %ju items, "
		    "not 2", sn->name, (uintmax_t)k));
	if ((error = head(r, 5, &k, "a map of annotations")) != 0 ||
	    (error = count(r, k, 2)) != 0)
		return (error);
	if (k > 0 && (*mv = ralloc(r, (size_t)k * sizeof(**mv))) == NULL)
		return (fail(r, ENOMEM, NOMEM));
	for (uint64_t i = 0; i < k; i++) {
		void *v;

		if ((error = dec_int(r, INT64_MIN, INT64_MAX, true, &u,
		    &delta)) != 0)
			return (error);
		an = cbl_yschema_annot(sn->module->schema, sn->sid +
		    (uint64_t)delta);
		if (an == NULL) {
			if (r->flags & CBL_YD_STRICT)
				return (fail(r, ENOENT, "%s: no annotation at "
				    "delta %jd", sn->name, (intmax_t)delta));
			if ((error = skip(r, depth)) != 0)
				return (error);
			continue;
		}
		if ((v = ralloc(r, an->type->csize > 0 ? an->type->csize :
		    1)) == NULL)
			return (fail(r, ENOMEM, NOMEM));
		r->leafmod = an->module;
		if ((error = dec_value(r, an->type, v, false)) != 0)
			return (error);
		(*mv)[*nm].an = an;
		(*mv)[(*nm)++].v = v;
	}
	return (0);
}

static int
put_meta(struct yrd *r, cbl_dnode *x, const struct ymeta *mv, size_t nm)
{
	int error;

	for (size_t i = 0; i < nm; i++)
		if ((error = cbl_dnode_meta_set(x, mv[i].an, mv[i].v)) != 0)
			return (fail(r, error, "%s: annotation %s",
			    x->sn->name, mv[i].an->name));
	return (0);
}

static int	dec_tmap(struct yrd *, cbl_dnode *, int);

static int
made(struct yrd *r, int error, const struct cbl_ynode *sn)
{

	if (error == 0)
		return (0);
	return (fail(r, error, "%s: %s", sn->name, error == EEXIST ?
	    "there already, or twice" : error == ENOMEM ? NOMEM :
	    "not where its schema has it"));
}

/* An entry of list sn: its keys read first, wherever they are. */
static int
dec_entry(struct yrd *r, cbl_dnode *parent, const struct cbl_ynode *sn,
    int depth, cbl_dnode **out)
{
	const void *keys[UINT8_MAX];
	const uint8_t *start = r->p;
	struct ymeta *mv;
	uint64_t k, u;
	int64_t delta;
	size_t nm;
	int error;

	if (sn->nkeys > nitems(keys))
		return (fail(r, EINVAL, "%s: too many keys", sn->name));
	memset(keys, 0, sizeof(keys));
	if ((error = head(r, 5, &k, "a map")) != 0 ||
	    (error = count(r, k, 2)) != 0)
		return (error);
	for (uint64_t i = 0; i < k; i++) {
		const struct cbl_ynode *c;
		uint16_t j = 0;
		void *v;

		if ((error = dec_int(r, INT64_MIN, INT64_MAX, true, &u,
		    &delta)) != 0)
			return (error);
		c = cbl_ynode_child(sn, delta);
		for (; c != NULL && j < sn->nkeys; j++)
			if (sn->child[sn->keys[j]] == c)
				break;
		if (c == NULL || j == sn->nkeys) {
			if ((error = skip(r, depth)) != 0)
				return (error);
			continue;
		}
		if ((error = dec_meta(r, c, &mv, &nm, depth)) != 0)
			return (error);
		if ((v = ralloc(r, c->type->csize > 0 ? c->type->csize :
		    1)) == NULL)
			return (fail(r, ENOMEM, NOMEM));
		r->leafmod = c->module;
		if ((error = dec_value(r, c->type, v, false)) != 0)
			return (error);
		keys[j] = v;
	}
	for (uint16_t j = 0; j < sn->nkeys; j++)
		if (keys[j] == NULL)
			return (fail(r, EINVAL, "%s: an entry without its key "
			    "%s", sn->name, sn->child[sn->keys[j]]->name));
	if ((error = made(r, cbl_dnode_add_entry(parent, sn, keys, out),
	    sn)) != 0)
		return (error);
	r->p = start;
	return (dec_tmap(r, *out, depth + 1));
}

/* One instance of sn, in its annotations or not, made a child of parent. */
static int
dec_tnode(struct yrd *r, cbl_dnode *parent, const struct cbl_ynode *sn,
    int depth, cbl_dnode **out)
{
	struct cbl_bytes by;
	struct ymeta *mv;
	cbl_dnode *x = NULL;
	size_t nm;
	void *v;
	int error;

	if ((error = dec_meta(r, sn, &mv, &nm, depth)) != 0)
		return (error);
	switch (sn->kind) {
	case CBL_YN_LEAF:
	case CBL_YN_LEAFLIST:
		if ((v = ralloc(r, sn->type->csize > 0 ? sn->type->csize :
		    1)) == NULL)
			return (fail(r, ENOMEM, NOMEM));
		r->leafmod = sn->module;
		if ((error = dec_value(r, sn->type, v, false)) != 0 ||
		    (error = made(r, cbl_dnode_add(parent, sn, v, &x), sn)) !=
		    0)
			return (error);
		break;
	case CBL_YN_ANYDATA:
	case CBL_YN_ANYXML:
		if ((error = raw(r, &by)) != 0 ||
		    (error = made(r, cbl_dnode_add(parent, sn, &by, &x), sn)) !=
		    0)
			return (error);
		break;
	case CBL_YN_LIST:
		if ((error = dec_entry(r, parent, sn, depth, &x)) != 0)
			return (error);
		break;
	default:
		if ((error = made(r, cbl_dnode_add(parent, sn, NULL, &x),
		    sn)) != 0 || (error = dec_tmap(r, x, depth + 1)) != 0)
			return (error);
		break;
	}
	if (out != NULL)
		*out = x;
	return (put_meta(r, x, mv, nm));
}

/* x's children, keyed by deltas from it (by SID at the root). */
static int
dec_tmap(struct yrd *r, cbl_dnode *x, int depth)
{
	const struct cbl_ynode *c;
	struct ymeta *mv;
	uint64_t k, u, n;
	int64_t delta;
	size_t nm;
	int error;

	if (depth > YDEPTH_MAX)
		return (fail(r, ELOOP, "nested too deep"));
	if ((error = head(r, 5, &k, "a map")) != 0 ||
	    (error = count(r, k, 2)) != 0)
		return (error);
	for (uint64_t i = 0; i < k; i++) {
		bool abs;

		if ((error = dec_key(r, &abs, &u, &delta)) != 0)
			return (error);
		/* The root's keys are SIDs; a mount point's, absolute ones
		 * (RFC 8528): a top-level node either way. */
		if (x->sn == NULL || (abs && (x->sn->flags &
		    CBL_YNF_MOUNT) != 0)) {
			uint64_t sid = abs ? u : (uint64_t)delta;

			c = abs || delta >= 0 ? cbl_yschema_node(x->tree->schema,
			    sid) : NULL;
			for (u = 0; c != NULL && u < x->tree->ntops &&
			    x->tree->tops[u] != c; u++)
				;
			if (c != NULL && u == x->tree->ntops)
				c = NULL;
			delta = (int64_t)sid;
		} else if (abs) {
			c = cbl_ynode_child(x->sn, (int64_t)(u -
			    cbl_ynode_base(x->sn)));
			delta = (int64_t)u;
		} else
			c = cbl_ynode_child(x->sn, delta);
		if (c == NULL) {
			if (r->flags & CBL_YD_STRICT)
				return (fail(r, ENOENT, "%s: no child at %s "
				    "%jd", x->sn != NULL ? x->sn->name :
				    "the top", x->sn != NULL ? "delta" : "SID",
				    (intmax_t)delta));
			if ((error = skip(r, depth)) != 0)
				return (error);
			continue;
		}
		/* An entry's key, made with it: its annotations only. */
		if ((c->flags & CBL_YNF_KEY) != 0 && x->sn != NULL &&
		    x->sn->kind == CBL_YN_LIST) {
			if ((error = dec_meta(r, c, &mv, &nm, depth)) != 0 ||
			    (error = skip(r, depth)) != 0 ||
			    (error = put_meta(r, cbl_dnode_child(x, c), mv,
			    nm)) != 0)
				return (error);
			continue;
		}
		if (c->kind != CBL_YN_LIST && c->kind != CBL_YN_LEAFLIST) {
			if ((error = dec_tnode(r, x, c, depth, NULL)) != 0)
				return (error);
			continue;
		}
		if ((error = head(r, 4, &n, "an array")) != 0 ||
		    (error = count(r, n, 1)) != 0)
			return (error);
		for (uint64_t j = 0; j < n; j++)
			if ((error = dec_tnode(r, x, c, depth, NULL)) != 0)
				return (error);
	}
	return (0);
}

int
cbl_d_decode(cbl_dnode *parent, const struct cbl_ynode *sn, const void *data,
    size_t len, int flags, char *why, size_t whylen, cbl_dnode **out)
{
	struct yrd r = { data, (const uint8_t *)data + len, data, NULL, flags,
	    why, whylen, NULL };
	cbl_dnode *x = NULL;
	int error;

	if (why != NULL && whylen > 0)
		why[0] = '\0';
	if (parent == NULL || data == NULL || (sn == NULL &&
	    parent->sn != NULL))
		return (EINVAL);
	if ((r.a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	error = sn == NULL ? dec_tmap(&r, parent, 0) : dec_tnode(&r, parent,
	    sn, 0, &x);
	if (error == 0 && r.p != r.end)
		error = fail(&r, EINVAL, "bytes after the value");
	cbl_yarena_free(r.a);
	if (error != 0 && x != NULL)
		(void)cbl_dnode_remove(x);
	if (error == 0 && out != NULL)
		*out = x;
	return (error);
}
