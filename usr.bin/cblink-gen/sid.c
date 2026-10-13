/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * ".sid" files (RFC 9595, sid.h).  The file is JSON in the shape of the
 * ietf-sid-file structure: read here with base's libucl; a uint64 is a
 * JSON string there (RFC 7951), a number is taken too.
 */

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <ucl.h>

#include "gen.h"
#include "schema.h"
#include "sid.h"

#define	SID_TOP		"ietf-sid-file:sid-file"
#define	SID_MAX		INT64_MAX	/* the sid typedef's range */

const char *
sid_ns_name(enum sid_ns ns)
{

	switch (ns) {
	case SID_NS_MODULE:	return ("module");
	case SID_NS_IDENTITY:	return ("identity");
	case SID_NS_FEATURE:	return ("feature");
	case SID_NS_DATA:	return ("data");
	}
	return ("?");
}

void
sid_free(struct sidfile *f)
{

	if (f == NULL)
		return;
	free(f->module);
	free(f->revision);
	free(f->status);
	free(f->description);
	for (size_t i = 0; i < f->ndeps; i++) {
		free(f->deps[i].module);
		free(f->deps[i].revision);
	}
	free(f->deps);
	free(f->ranges);
	for (size_t i = 0; i < f->nitems; i++)
		free(f->items[i].id);
	free(f->items);
	free(f);
}

static const char *
str_of(const ucl_object_t *o, const char *key, bool need, const char *where,
    struct diags *d)
{
	const ucl_object_t *v;

	if ((v = ucl_object_lookup(o, key)) == NULL) {
		if (need)
			diag_add(d, 0, 0, "%s: no \"%s\"", where, key);
		return (NULL);
	}
	if (ucl_object_type(v) != UCL_STRING) {
		diag_add(d, 0, 0, "%s: \"%s\" is not a string", where, key);
		return (NULL);
	}
	return (ucl_object_tostring(v));
}

/* A uint64 leaf: a decimal string (RFC 7951), or a number. */
static bool
u64_of(const ucl_object_t *o, const char *key, uint64_t max, uint64_t *vp,
    const char *where, struct diags *d)
{
	const ucl_object_t *v;
	const char *s;
	char *end;
	int64_t i;

	if ((v = ucl_object_lookup(o, key)) == NULL) {
		diag_add(d, 0, 0, "%s: no \"%s\"", where, key);
		return (false);
	}
	if (ucl_object_type(v) == UCL_INT) {
		i = ucl_object_toint(v);
		if (i < 0 || (uint64_t)i > max)
			goto range;
		*vp = (uint64_t)i;
		return (true);
	}
	if (ucl_object_type(v) != UCL_STRING ||
	    (s = ucl_object_tostring(v)) == NULL || *s < '0' || *s > '9') {
		diag_add(d, 0, 0, "%s: \"%s\" is not a number", where, key);
		return (false);
	}
	errno = 0;
	*vp = strtoumax(s, &end, 10);
	if (errno != 0 || *end != '\0' || *vp > max)
		goto range;
	return (true);
range:
	diag_add(d, 0, 0, "%s: \"%s\" out of range", where, key);
	return (false);
}

struct sidfile *
sid_read(const char *text, size_t len, struct diags *d)
{
	struct ucl_parser *up;
	const ucl_object_t *top, *f, *a, *e;
	ucl_object_iter_t it;
	struct sidfile *sf;
	const char *s;
	uint64_t v;
	size_t errs = d->n;

	/* A map of one: the CBOR form. */
	if (len > 0 && (unsigned char)text[0] == 0xa1)
		return (sid_read_cbor(text, len, d));
	if ((up = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME)) == NULL)
		errx(2, "libucl: no memory");
	if (!ucl_parser_add_chunk_full(up, (const unsigned char *)text, len,
	    0, UCL_DUPLICATE_ERROR, UCL_PARSE_UCL)) {
		diag_add(d, 0, 0, "not JSON: %s", ucl_parser_get_error(up));
		ucl_parser_free(up);
		return (NULL);
	}
	top = ucl_parser_get_object(up);
	ucl_parser_free(up);
	if ((f = ucl_object_lookup(top, SID_TOP)) == NULL ||
	    ucl_object_type(f) != UCL_OBJECT) {
		diag_add(d, 0, 0, "no \"%s\" object", SID_TOP);
		ucl_object_unref((ucl_object_t *)(uintptr_t)top);
		return (NULL);
	}
	sf = xcalloc(1, sizeof(*sf));
	if ((s = str_of(f, "module-name", true, "the file", d)) != NULL)
		sf->module = xstrdup(s);
	if ((s = str_of(f, "module-revision", false, "the file", d)) != NULL)
		sf->revision = xstrdup(s);
	if (ucl_object_lookup(f, "sid-file-version") != NULL &&
	    u64_of(f, "sid-file-version", UINT32_MAX, &v, "the file", d)) {
		sf->has_version = true;
		sf->version = (uint32_t)v;
	}
	if ((s = str_of(f, "sid-file-status", false, "the file", d)) != NULL) {
		if (strcmp(s, "published") != 0 &&
		    strcmp(s, "unpublished") != 0)
			diag_add(d, 0, 0, "sid-file-status \"%s\"", s);
		sf->status = xstrdup(s);
	}
	if ((s = str_of(f, "description", false, "the file", d)) != NULL)
		sf->description = xstrdup(s);

	if ((a = ucl_object_lookup(f, "dependency-revision")) != NULL) {
		it = NULL;
		while ((e = ucl_object_iterate(a, &it, true)) != NULL) {
			const char *m, *r;

			m = str_of(e, "module-name", true,
			    "dependency-revision", d);
			r = str_of(e, "module-revision", true,
			    "dependency-revision", d);
			if (m == NULL || r == NULL)
				continue;
			sf->deps = xreallocarray(sf->deps, sf->ndeps + 1,
			    sizeof(*sf->deps));
			sf->deps[sf->ndeps].module = xstrdup(m);
			sf->deps[sf->ndeps++].revision = xstrdup(r);
		}
	}
	if ((a = ucl_object_lookup(f, "assignment-range")) != NULL) {
		it = NULL;
		while ((e = ucl_object_iterate(a, &it, true)) != NULL) {
			uint64_t entry, size;

			if (!u64_of(e, "entry-point", SID_MAX, &entry,
			    "assignment-range", d) || !u64_of(e, "size",
			    UINT64_MAX, &size, "assignment-range", d))
				continue;
			if (size == 0 || size - 1 > SID_MAX - entry) {
				diag_add(d, 0, 0, "assignment-range %" PRIu64
				    "+%" PRIu64 ": empty or past the largest SID",
				    entry, size);
				continue;
			}
			sf->ranges = xreallocarray(sf->ranges, sf->nranges + 1,
			    sizeof(*sf->ranges));
			sf->ranges[sf->nranges].entry = entry;
			sf->ranges[sf->nranges++].size = size;
		}
	}
	if ((a = ucl_object_lookup(f, "item")) != NULL) {
		it = NULL;
		while ((e = ucl_object_iterate(a, &it, true)) != NULL) {
			struct siditem item = { 0 };
			const char *ns, *id, *st;

			ns = str_of(e, "namespace", true, "item", d);
			id = str_of(e, "identifier", true, "item", d);
			st = str_of(e, "status", false, "item", d);
			if (ns == NULL || id == NULL ||
			    !u64_of(e, "sid", SID_MAX, &item.sid, id, d))
				continue;
			if (strcmp(ns, "module") == 0)
				item.ns = SID_NS_MODULE;
			else if (strcmp(ns, "identity") == 0)
				item.ns = SID_NS_IDENTITY;
			else if (strcmp(ns, "feature") == 0)
				item.ns = SID_NS_FEATURE;
			else if (strcmp(ns, "data") == 0)
				item.ns = SID_NS_DATA;
			else {
				diag_add(d, 0, 0, "%s: namespace \"%s\"", id,
				    ns);
				continue;
			}
			if (st == NULL)
				item.status = SID_ST_NONE;
			else if (strcmp(st, "stable") == 0)
				item.status = SID_ST_STABLE;
			else if (strcmp(st, "unstable") == 0)
				item.status = SID_ST_UNSTABLE;
			else if (strcmp(st, "obsolete") == 0)
				item.status = SID_ST_OBSOLETE;
			else {
				diag_add(d, 0, 0, "%s: status \"%s\"", id, st);
				continue;
			}
			item.id = xstrdup(id);
			sf->items = xreallocarray(sf->items, sf->nitems + 1,
			    sizeof(*sf->items));
			sf->items[sf->nitems++] = item;
		}
	}
	ucl_object_unref((ucl_object_t *)(uintptr_t)top);
	if (d->n > errs || sf->module == NULL) {
		sid_free(sf);
		return (NULL);
	}
	return (sf);
}

/*
 * Attaching: the items of a file to the schema's items of its module.
 */

struct attach {
	const struct smodule	*m;
	const char		*path;	/* the data item looked for */
	struct snode		*found;
};

static void
find_node(struct snode *n, void *arg)
{
	struct attach *a = arg;
	struct buf b;

	if (a->found != NULL || n->module != a->m)
		return;
	buf_init(&b);
	if (snode_sid_path(n, &b) && strcmp(b.p, a->path) == 0)
		a->found = n;
	buf_free(&b);
}

static void
walk_in(struct snode *n, snode_visit_t *visit, void *arg)
{

	for (; n != NULL; n = n->next) {
		visit(n, arg);
		for (size_t i = 0; i < n->nexts; i++)
			walk_in(n->exts[i].data, visit, arg);
		walk_in(n->child, visit, arg);
	}
}

/* Every node of the schema, those inside extension instances too. */
static void
walk_all(struct schema *s, snode_visit_t *visit, void *arg)
{

	for (size_t i = 0; i < s->nmods; i++) {
		struct smodule *m = s->mods[i];

		walk_in(m->data, visit, arg);
		walk_in(m->rpcs, visit, arg);
		walk_in(m->notifs, visit, arg);
		for (size_t j = 0; j < m->nexts; j++)
			walk_in(m->exts[j].data, visit, arg);
	}
}

/* A structure of m: /m:name. */
static struct sext *
find_structure(struct smodule *m, const char *path)
{
	size_t len = strlen(m->name);

	if (path[0] != '/' || strncmp(path + 1, m->name, len) != 0 ||
	    path[len + 1] != ':')
		return (NULL);
	for (size_t i = 0; i < m->nexts; i++)
		if (sext_is_structure(&m->exts[i], m) &&
		    strcmp(m->exts[i].arg, path + len + 2) == 0)
			return (&m->exts[i]);
	return (NULL);
}

int
sid_attach(struct schema *s, const struct sidfile *f, struct diags *d)
{
	struct smodule *m;
	struct attach a;
	struct sext *st;
	size_t errs = d->n;
	bool found;

	if ((m = schema_module(s, f->module, f->revision)) == NULL) {
		diag_add(d, 0, 0, "the file is for %s%s%s, not in the schema",
		    f->module, f->revision != NULL ? "@" : "",
		    f->revision != NULL ? f->revision : "");
		return (-1);
	}
	for (size_t i = 0; i < f->nitems; i++) {
		const struct siditem *it = &f->items[i];

		found = false;
		switch (it->ns) {
		case SID_NS_MODULE:
			if ((found = strcmp(it->id, m->name) == 0))
				m->sid = it->sid;
			break;
		case SID_NS_IDENTITY:
			for (size_t j = 0; j < m->nidents && !found; j++)
				if ((found = strcmp(m->idents[j].name,
				    it->id) == 0))
					m->idents[j].sid = it->sid;
			break;
		case SID_NS_FEATURE:
			for (size_t j = 0; j < m->nfeatures && !found; j++)
				if ((found = strcmp(m->features[j].name,
				    it->id) == 0))
					m->features[j].sid = it->sid;
			break;
		case SID_NS_DATA:
			if ((st = find_structure(m, it->id)) != NULL) {
				st->sid = it->sid;
				found = true;
				break;
			}
			a = (struct attach){ .m = m, .path = it->id };
			walk_all(s, find_node, &a);
			if ((found = a.found != NULL))
				a.found->sid = it->sid;
			break;
		}
		/* An obsolete item may name what the schema no longer has. */
		if (!found && it->status != SID_ST_OBSOLETE)
			diag_add(d, 0, 0, "%s %s: not in %s", sid_ns_name(it->ns),
			    it->id, m->name);
	}
	return (d->n > errs ? -1 : 0);
}

/*
 * Verifying.
 */

static int
sid_cmp(const void *a, const void *b)
{
	const struct siditem *x = *(const struct siditem *const *)a;
	const struct siditem *y = *(const struct siditem *const *)b;

	return ((x->sid > y->sid) - (x->sid < y->sid));
}

static int
id_cmp(const void *a, const void *b)
{
	const struct siditem *x = *(const struct siditem *const *)a;
	const struct siditem *y = *(const struct siditem *const *)b;

	if (x->ns != y->ns)
		return ((x->ns > y->ns) - (x->ns < y->ns));
	return (strcmp(x->id, y->id));
}

struct missing {
	const struct smodule	*m;
	struct diags		*d;
};

static void
need_sid(struct snode *n, void *arg)
{
	struct missing *ms = arg;
	struct buf b;

	if (n->module != ms->m || n->sid != 0)
		return;
	/* Empty input and output too: RFC 9595 Appendix B says they MUST
	 * have one, though its own example (Appendix A) gives them none. */
	buf_init(&b);
	if (snode_sid_path(n, &b))
		diag_add(ms->d, 0, 0, "data %s: no SID", b.p);
	buf_free(&b);
}

int
sid_verify(struct schema *s, const struct sidfile *f, struct diags *d)
{
	const struct siditem **v;
	struct smodule *m;
	struct missing ms;
	size_t errs = d->n, i, j;

	if (f->nitems == 0) {
		diag_add(d, 0, 0, "no item");
		return (-1);
	}
	v = xcalloc(f->nitems, sizeof(*v));
	for (i = 0; i < f->nitems; i++)
		v[i] = &f->items[i];

	/* A SID is one item's, an item has one SID. */
	qsort(v, f->nitems, sizeof(*v), sid_cmp);
	for (i = 1; i < f->nitems; i++)
		if (v[i]->sid == v[i - 1]->sid)
			diag_add(d, 0, 0, "SID %" PRIu64 " given to %s %s and "
			    "%s %s", v[i]->sid, sid_ns_name(v[i - 1]->ns),
			    v[i - 1]->id, sid_ns_name(v[i]->ns), v[i]->id);
	qsort(v, f->nitems, sizeof(*v), id_cmp);
	for (i = 1; i < f->nitems; i++)
		if (id_cmp(&v[i], &v[i - 1]) == 0)
			diag_add(d, 0, 0, "%s %s has two SIDs, %" PRIu64 " and %"
			    PRIu64, sid_ns_name(v[i]->ns), v[i]->id,
			    v[i - 1]->sid, v[i]->sid);
	free(v);

	/* Inside the ranges the file was given, when it says any. */
	for (i = 0; f->nranges > 0 && i < f->nitems; i++) {
		for (j = 0; j < f->nranges; j++)
			if (f->items[i].sid >= f->ranges[j].entry &&
			    f->items[i].sid - f->ranges[j].entry <
			    f->ranges[j].size)
				break;
		if (j == f->nranges)
			diag_add(d, 0, 0, "%s %s: SID %" PRIu64 " outside the "
			    "file's assignment ranges",
			    sid_ns_name(f->items[i].ns), f->items[i].id,
			    f->items[i].sid);
	}

	/* Every item of the module has one. */
	if ((m = schema_module(s, f->module, f->revision)) == NULL)
		return (-1);
	if (m->sid == 0)
		diag_add(d, 0, 0, "module %s: no SID", m->name);
	for (i = 0; i < m->nidents; i++)
		if (m->idents[i].sid == 0)
			diag_add(d, 0, 0, "identity %s: no SID",
			    m->idents[i].name);
	for (i = 0; i < m->nfeatures; i++)
		if (m->features[i].sid == 0)
			diag_add(d, 0, 0, "feature %s: no SID",
			    m->features[i].name);
	for (i = 0; i < m->nexts; i++)
		if (sext_is_structure(&m->exts[i], m) &&
		    m->exts[i].sid == 0)
			diag_add(d, 0, 0, "data /%s:%s: no SID", m->name,
			    m->exts[i].arg);
	ms = (struct missing){ .m = m, .d = d };
	walk_all(s, need_sid, &ms);
	return (d->n > errs ? -1 : 0);
}

/*
 * Assigning.
 */

struct collect {
	const struct smodule	*m;
	struct siditem		*v;
	size_t			 n;
};

static void
collect_add(struct collect *c, enum sid_ns ns, char *id)
{

	c->v = xreallocarray(c->v, c->n + 1, sizeof(*c->v));
	c->v[c->n].ns = ns;
	c->v[c->n].id = id;
	c->v[c->n].status = SID_ST_NONE;
	c->v[c->n++].sid = 0;
}

/* A data node of the module without a SID; every one, empty input and
 * output included (RFC 9595 Appendix B: they MUST have one). */
static void
collect_node(struct snode *n, void *arg)
{
	struct collect *c = arg;
	struct buf b;

	if (n->module != c->m || n->sid != 0)
		return;
	buf_init(&b);
	if (snode_sid_path(n, &b))
		collect_add(c, SID_NS_DATA, xstrdup(b.p));
	buf_free(&b);
}

static int
item_order(const void *a, const void *b)
{
	const struct siditem *x = a, *y = b;

	if (x->ns != y->ns)
		return ((x->ns > y->ns) - (x->ns < y->ns));
	return (strcmp(x->id, y->id));
}

static int
u64_cmp(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return ((x > y) - (x < y));
}

static int
by_sid(const void *a, const void *b)
{
	const struct siditem *x = a, *y = b;

	return ((x->sid > y->sid) - (x->sid < y->sid));
}

int
sid_assign(struct schema *s, struct sidfile *f, struct diags *d)
{
	struct collect c = { 0 };
	struct smodule *m;
	uint64_t *used, next;
	size_t nused, before, i, r, u;

	if ((m = schema_module(s, f->module, f->revision)) == NULL) {
		diag_add(d, 0, 0, "the file is for %s, not in the schema",
		    f->module);
		return (-1);
	}
	c.m = m;
	if (m->sid == 0)
		collect_add(&c, SID_NS_MODULE, xstrdup(m->name));
	for (i = 0; i < m->nidents; i++)
		if (m->idents[i].sid == 0)
			collect_add(&c, SID_NS_IDENTITY,
			    xstrdup(m->idents[i].name));
	for (i = 0; i < m->nfeatures; i++)
		if (m->features[i].sid == 0)
			collect_add(&c, SID_NS_FEATURE,
			    xstrdup(m->features[i].name));
	for (i = 0; i < m->nexts; i++)
		if (sext_is_structure(&m->exts[i], m) &&
		    m->exts[i].sid == 0)
			collect_add(&c, SID_NS_DATA, xasprintf("/%s:%s",
			    m->name, m->exts[i].arg));
	walk_all(s, collect_node, &c);
	if (c.n == 0)
		return (0);
	if (f->nranges == 0) {
		diag_add(d, 0, 0, "%zu items to number, and the file has no "
		    "assignment range", c.n);
		goto fail;
	}
	qsort(c.v, c.n, sizeof(*c.v), item_order);

	/* The SIDs taken, to go past. */
	nused = f->nitems;
	used = xcalloc(nused + 1, sizeof(*used));
	for (i = 0; i < nused; i++)
		used[i] = f->items[i].sid;
	qsort(used, nused, sizeof(*used), u64_cmp);
	r = 0;
	next = f->ranges[0].entry;
	u = 0;
	for (i = 0; i < c.n; i++) {
		for (;;) {
			while (u < nused && used[u] < next)
				u++;
			if (r == f->nranges)
				break;
			if (next - f->ranges[r].entry >= f->ranges[r].size) {
				if (++r < f->nranges)
					next = f->ranges[r].entry;
				u = 0;
				continue;
			}
			if (u < nused && used[u] == next) {
				next++;
				continue;
			}
			break;
		}
		if (r == f->nranges) {
			diag_add(d, 0, 0, "the file's assignment ranges are "
			    "full: %zu items left without a SID; add a range",
			    c.n - i);
			free(used);
			goto fail;
		}
		c.v[i].sid = next++;
	}
	free(used);

	before = f->nitems;
	f->items = xreallocarray(f->items, f->nitems + c.n, sizeof(*f->items));
	memcpy(f->items + f->nitems, c.v, c.n * sizeof(*c.v));
	f->nitems += c.n;
	free(c.v);
	qsort(f->items, f->nitems, sizeof(*f->items), by_sid);
	/* A file that had items is a new version of itself. */
	if (before > 0) {
		f->version = f->has_version ? f->version + 1 : 1;
		f->has_version = true;
	}
	if (f->revision == NULL && m->revision != NULL)
		f->revision = xstrdup(m->revision);
	/* Its dependencies, as they are bound now. */
	for (i = 0; i < f->ndeps; i++) {
		free(f->deps[i].module);
		free(f->deps[i].revision);
	}
	f->ndeps = 0;
	for (i = 0; i < m->nimports; i++) {
		if (m->imports[i].revision == NULL)
			continue;
		f->deps = xreallocarray(f->deps, f->ndeps + 1,
		    sizeof(*f->deps));
		f->deps[f->ndeps].module = xstrdup(m->imports[i].name);
		f->deps[f->ndeps++].revision =
		    xstrdup(m->imports[i].revision);
	}
	return ((int)c.n);
fail:
	for (i = 0; i < c.n; i++)
		free(c.v[i].id);
	free(c.v);
	return (-1);
}

/*
 * Writing.
 */

static void
json_str(struct buf *b, const char *s)
{

	buf_puts(b, "\"");
	for (; *s != '\0'; s++) {
		unsigned char ch = (unsigned char)*s;

		if (ch == '"' || ch == '\\')
			buf_printf(b, "\\%c", ch);
		else if (ch == '\n')
			buf_puts(b, "\\n");
		else if (ch == '\t')
			buf_puts(b, "\\t");
		else if (ch < 0x20)
			buf_printf(b, "\\u%04x", ch);
		else
			buf_add(b, s, 1);
	}
	buf_puts(b, "\"");
}

void
sid_write(const struct sidfile *f, struct buf *b)
{
	static const char *const st[] = {
		[SID_ST_STABLE] = "stable", [SID_ST_UNSTABLE] = "unstable",
		[SID_ST_OBSOLETE] = "obsolete",
	};
	size_t i;

	buf_puts(b, "{\n  \"ietf-sid-file:sid-file\": {\n    \"module-name\": ");
	json_str(b, f->module);
	if (f->revision != NULL) {
		buf_puts(b, ",\n    \"module-revision\": ");
		json_str(b, f->revision);
	}
	if (f->has_version)
		buf_printf(b, ",\n    \"sid-file-version\": %u", f->version);
	if (f->status != NULL) {
		buf_puts(b, ",\n    \"sid-file-status\": ");
		json_str(b, f->status);
	}
	if (f->description != NULL) {
		buf_puts(b, ",\n    \"description\": ");
		json_str(b, f->description);
	}
	if (f->ndeps > 0) {
		buf_puts(b, ",\n    \"dependency-revision\": [");
		for (i = 0; i < f->ndeps; i++) {
			buf_printf(b, "%s\n      {\n        \"module-name\": ",
			    i > 0 ? "," : "");
			json_str(b, f->deps[i].module);
			buf_puts(b, ",\n        \"module-revision\": ");
			json_str(b, f->deps[i].revision);
			buf_puts(b, "\n      }");
		}
		buf_puts(b, "\n    ]");
	}
	if (f->nranges > 0) {
		buf_puts(b, ",\n    \"assignment-range\": [");
		for (i = 0; i < f->nranges; i++)
			buf_printf(b, "%s\n      {\n        \"entry-point\": "
			    "\"%" PRIu64 "\",\n        \"size\": \"%" PRIu64
			    "\"\n      }", i > 0 ? "," : "", f->ranges[i].entry,
			    f->ranges[i].size);
		buf_puts(b, "\n    ]");
	}
	if (f->nitems > 0) {
		buf_puts(b, ",\n    \"item\": [");
		for (i = 0; i < f->nitems; i++) {
			buf_printf(b, "%s\n      {\n        \"namespace\": "
			    "\"%s\",\n        \"identifier\": ", i > 0 ? "," :
			    "", sid_ns_name(f->items[i].ns));
			json_str(b, f->items[i].id);
			if (f->items[i].status != SID_ST_NONE)
				buf_printf(b, ",\n        \"status\": \"%s\"",
				    st[f->items[i].status]);
			buf_printf(b, ",\n        \"sid\": \"%" PRIu64 "\"\n"
			    "      }", f->items[i].sid);
		}
		buf_puts(b, "\n    ]");
	}
	buf_puts(b, "\n  }\n}\n");
}
