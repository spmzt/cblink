/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gen.h"

void *
xcalloc(size_t n, size_t size)
{
	void *p;

	if ((p = calloc(n == 0 ? 1 : n, size == 0 ? 1 : size)) == NULL)
		err(2, "calloc");
	return (p);
}

void *
xreallocarray(void *p, size_t n, size_t size)
{

	if ((p = reallocarray(p, n == 0 ? 1 : n, size)) == NULL)
		err(2, "reallocarray");
	return (p);
}

char *
xstrndup(const char *s, size_t len)
{
	char *p;

	if ((p = strndup(s, len)) == NULL)
		err(2, "strndup");
	return (p);
}

char *
xstrdup(const char *s)
{

	return (xstrndup(s, strlen(s)));
}

void
buf_init(struct buf *b)
{

	b->p = NULL;
	b->len = 0;
	b->cap = 0;
}

void
buf_free(struct buf *b)
{

	free(b->p);
	buf_init(b);
}

void
buf_add(struct buf *b, const char *s, size_t len)
{
	size_t ncap;

	if (b->len + len + 1 > b->cap) {
		ncap = b->cap == 0 ? 1024 : b->cap;
		while (ncap < b->len + len + 1)
			ncap *= 2;
		b->p = xreallocarray(b->p, ncap, 1);
		b->cap = ncap;
	}
	memcpy(b->p + b->len, s, len);
	b->len += len;
	b->p[b->len] = '\0';
}

void
buf_puts(struct buf *b, const char *s)
{

	buf_add(b, s, strlen(s));
}

void
buf_vprintf(struct buf *b, const char *fmt, va_list ap)
{
	char *s;
	int n;

	if ((n = vasprintf(&s, fmt, ap)) == -1)
		err(2, "vasprintf");
	buf_add(b, s, (size_t)n);
	free(s);
}

void
buf_printf(struct buf *b, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	buf_vprintf(b, fmt, ap);
	va_end(ap);
}

void
diag_add(struct diags *d, int line, int col, const char *fmt, ...)
{
	va_list ap;
	char *s;

	if (d->n == d->cap) {
		d->cap = d->cap == 0 ? 16 : d->cap * 2;
		d->v = xreallocarray(d->v, d->cap, sizeof(*d->v));
	}
	va_start(ap, fmt);
	if (vasprintf(&s, fmt, ap) == -1)
		err(2, "vasprintf");
	va_end(ap);
	d->v[d->n].line = line;
	d->v[d->n].col = col;
	d->v[d->n].msg = s;
	d->n++;
}

static int
diag_cmp(const void *a, const void *b)
{
	const struct diag *x = a, *y = b;

	if (x->line != y->line)
		return (x->line < y->line ? -1 : 1);
	if (x->col != y->col)
		return (x->col < y->col ? -1 : 1);
	return (strcmp(x->msg, y->msg));
}

/* Print sorted by location, at most DIAG_MAX, for stable output. */
void
diag_print(struct diags *d)
{

	qsort(d->v, d->n, sizeof(*d->v), diag_cmp);
	for (size_t i = 0; i < d->n && i < DIAG_MAX; i++)
		fprintf(stderr, "%s:%d:%d: error: %s\n", d->file, d->v[i].line,
		    d->v[i].col, d->v[i].msg);
	if (d->n > DIAG_MAX)
		fprintf(stderr, "%s: too many errors (%zu), stopping\n",
		    d->file, d->n);
}

void
diag_free(struct diags *d)
{

	for (size_t i = 0; i < d->n; i++)
		free(d->v[i].msg);
	free(d->v);
	d->v = NULL;
	d->n = d->cap = 0;
}

char *
xasprintf(const char *fmt, ...)
{
	va_list ap;
	char *s;

	va_start(ap, fmt);
	if (vasprintf(&s, fmt, ap) == -1)
		err(2, "vasprintf");
	va_end(ap);
	return (s);
}
