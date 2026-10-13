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
		if (m->exts[i].arg != NULL && !m->exts[i].inherited &&
		    m->exts[i].module == m &&
		    strcmp(m->exts[i].ext,
		    "ietf-yang-structure-ext:structure") == 0 &&
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
