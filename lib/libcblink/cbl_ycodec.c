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

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_impl.h"
#include "cbl_schema.h"

#define	YDEPTH_MAX	CBL_DEPTH_HARD_MAX

struct cbl_yarena {
	struct cbl_arena	 ar;
};

cbl_yarena *
cbl_yarena_new(void)
{
	cbl_yarena *a;

	if ((a = calloc(1, sizeof(*a))) == NULL)
		return (NULL);
	cbl_arena_init(&a->ar);
	return (a);
}

void
cbl_yarena_free(cbl_yarena *a)
{

	if (a == NULL)
		return;
	cbl_arena_free(&a->ar);
	free(a);
}

void *
cbl_yarena_alloc(cbl_yarena *a, size_t len)
{
	void *p;

	if (a == NULL)
		return (NULL);
	if ((p = cbl_arena_alloc(&a->ar, len == 0 ? 1 : len)) != NULL)
		memset(p, 0, len == 0 ? 1 : len);
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
	case CBL_YT_BINARY:
	case CBL_YT_BITS:
		by = v;
		if (inunion && t->kind == CBL_YT_BITS &&
		    (error = put_head(b, 6, 43)) != 0)
			return (error);
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
	if ((error = put_head(b, 5, k)) != 0)
		return (error);
	for (uint32_t i = 0; i < n->nchild; i++) {
		const struct cbl_ynode *c = n->child[i];

		if (!present(c, p))
			continue;
		if ((error = put_int(b, (int64_t)(c->sid - n->sid))) != 0 ||
		    (error = enc_child(b, c, p, depth)) != 0)
			return (error);
	}
	return (0);
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

/*
 * Decoding.
 */

struct yrd {
	const uint8_t	*p, *end, *start;
	cbl_yarena	*a;
	int		 flags;
	char		*why;
	size_t		 whylen;
};

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

static void *
ralloc(struct yrd *r, size_t len)
{
	void *p;

	if ((p = cbl_arena_alloc(&r->a->ar, len == 0 ? 1 : len)) != NULL)
		memset(p, 0, len == 0 ? 1 : len);
	return (p);
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
		return (fail(r, ENOMEM, "no memory"));
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
	if ((s = ralloc(r, (size_t)len + 1)) == NULL)
		return (fail(r, ENOMEM, "no memory"));
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
		return (fail(r, ENOMEM, "no memory"));
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
 * Which member of union t the next item is, by what it is: its tag, or
 * its major type; -1 none.
 */
static int
member(struct yrd *r, const struct cbl_ytype *t)
{
	unsigned major, kind;
	uint64_t arg;
	size_t hlen;

	if (peek(r, &major, &arg, &hlen) != 0)
		return (-1);
	for (uint16_t i = 0; i < t->nmembers; i++) {
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
		if (kind == CBL_YT_UNION && member(r, t->members[i]) >= 0)
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
			return (fail(r, EINVAL, "a decimal64 (tag 4) expected"));
		if ((error = head(r, 4, &arg, "[exponent, mantissa]")) != 0)
			return (error);
		if (arg != 2)
			return (fail(r, EINVAL, "[exponent, mantissa] expected"));
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
		if (inunion && !tag(r, 43))
			return (fail(r, EINVAL, "bits (tag 43) expected"));
		return (dec_bytes(r, v));
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
		if ((error = dec_int(r, 0, UINT64_MAX, false, &u, &s)) != 0)
			return (error);
		*(uint64_t *)v = u;
		return (0);
	case CBL_YT_INSTANCEID:
		if (inunion && !tag(r, 46))
			return (fail(r, EINVAL, "an instance-identifier (tag "
			    "46) expected"));
		return (raw(r, v));
	case CBL_YT_UNION:
		if ((m = member(r, t)) < 0)
			return (fail(r, EINVAL, "no member of the union is "
			    "this"));
		*(unsigned *)v = (unsigned)m;
		return (dec_value(r, t->members[m], WAT(v, t->voff), true));
	}
	return (fail(r, EINVAL, "a type not known"));
}

static int	dec_map(struct yrd *, const struct cbl_ynode *, void *, int);

/* Child n's value into struct p. */
static int
dec_child(struct yrd *r, const struct cbl_ynode *n, void *p, int depth)
{
	struct yarr *a;
	uint64_t k;
	void *q;
	int error;

	switch (n->kind) {
	case CBL_YN_CONTAINER:
		if ((q = ralloc(r, n->size)) == NULL)
			return (fail(r, ENOMEM, "no memory"));
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
			return (fail(r, ENOMEM, "no memory"));
		a = (struct yarr *)WAT(p, n->off);
		a->n = (size_t)k;
		a->v = q;
		for (uint64_t i = 0; i < k; i++) {
			error = n->kind == CBL_YN_LIST ? dec_map(r, n,
			    WAT(q, i * n->size), depth + 1) : dec_value(r,
			    n->type, WAT(q, i * n->type->csize), false);
			if (error != 0)
				return (error);
		}
		return (0);
	case CBL_YN_LEAF:
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
	const struct cbl_ychoice *c = n->choice;
	uint32_t want = n->ccase;
	int had;

	for (; c != NULL; want = c->parent_case, c = c->parent) {
		if (c->off == CBL_YOFF_NONE)
			continue;
		had = read_enum(AT(p, c->off), sizeof(int));
		if (had != 0 && (uint32_t)had != want + 1)
			return (fail(r, EINVAL, "%s: two cases of choice %s",
			    n->name, c->name));
		write_enum(WAT(p, c->off), sizeof(int), (int)want + 1);
	}
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
		return (fail(r, ENOMEM, "no memory"));
	for (uint64_t i = 0; i < k && error == 0; i++) {
		if ((error = dec_int(r, INT64_MIN, INT64_MAX, true, &u,
		    &delta)) != 0)
			break;
		c = cbl_ynode_child(n, delta);
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
	    why, whylen };
	int error;

	if (why != NULL && whylen > 0)
		why[0] = '\0';
	if (n == NULL || data == NULL || p == NULL || a == NULL)
		return (EINVAL);
	if ((error = dec_map(&r, n, p, 0)) != 0)
		return (error);
	if (r.p != r.end)
		return (fail(&r, EINVAL, "bytes after the value"));
	return (0);
}
