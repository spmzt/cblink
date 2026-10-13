/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Markdown reference of YANG modules, from the generator's schema model:
 * a page for each module named on the command line, with its tree
 * diagram and a table of the nodes it defines, wherever they are (its
 * own tree, other modules' trees it augments, its structures), with
 * their SIDs when its .sid file is attached; then its features and its
 * identities.
 */

#include <inttypes.h>
#include <string.h>

#include "gen.h"
#include "schema.h"

/* Table cells must stay on one line and not break the table. */
static void
cell(struct buf *b, const char *s)
{

	for (; *s != '\0'; s++) {
		if (*s == '\n' || *s == '\r' || *s == '\t')
			buf_puts(b, " ");
		else if (*s == '|')
			buf_puts(b, "\\|");
		else
			buf_add(b, s, 1);
	}
}

static void
code(struct buf *b, const char *s)
{

	buf_puts(b, "`");
	cell(b, s);
	buf_puts(b, "`");
}

/*
 * A node's path: a data node's as its .sid file names it, a choice or a
 * case after its parent's, in the parentheses of the tree diagram.
 */
static void
path(struct buf *b, const struct snode *n)
{

	if (n->kind != SN_CHOICE && n->kind != SN_CASE) {
		snode_sid_path(n, b);
		return;
	}
	if (n->parent != NULL)
		path(b, n->parent);
	else if (n->in != NULL)
		buf_printf(b, "/%s:%s", n->in->module->name, n->in->arg);
	buf_puts(b, n->kind == SN_CASE ? "/:(" : "/(");
	if (n->parent == NULL || n->parent->module != n->module)
		buf_printf(b, "%s:", n->module->name);
	buf_printf(b, "%s)", n->name);
}

/* In an operation or a notification, where nothing is config. */
static bool
in_operation(const struct snode *n)
{

	for (; n != NULL; n = n->parent)
		if (n->kind == SN_RPC || n->kind == SN_ACTION ||
		    n->kind == SN_NOTIF)
			return (true);
	return (false);
}

static void
type(struct buf *b, const struct snode *n)
{
	const char *base;

	if (n->type == NULL)
		return;
	base = sntype_base_name(n->type->base);
	if (n->wpath != NULL) {
		buf_printf(b, "%s ", base);
		code(b, n->wpath);
		return;
	}
	code(b, n->wtype != NULL ? n->wtype : base);
	if (n->wtype != NULL && strcmp(n->wtype, base) != 0)
		buf_printf(b, " (%s)", base);
}

/*
 * Mandatory as RFC 7950 has it: a leaf, a choice, anydata, anyxml; a list
 * or leaf-list by its min-elements.  (libyang marks a container with a
 * mandatory node in it too, which is not what the statement means.)
 */
static void
mandatory(struct buf *b, const struct snode *n)
{

	switch (n->kind) {
	case SN_LEAF:
	case SN_CHOICE:
	case SN_ANYDATA:
	case SN_ANYXML:
		if ((n->flags & SNF_MANDATORY) != 0)
			buf_puts(b, "yes");
		break;
	case SN_LIST:
	case SN_LEAFLIST:
		if (n->min > 0)
			buf_printf(b, "min-elements %" PRIu32, n->min);
		break;
	default:
		break;
	}
}

struct rows {
	struct buf		*b;
	const struct smodule	*m;
	bool			 sids;
};

static void
row(const struct snode *n, struct rows *r)
{
	struct buf *b = r->b;

	for (; n != NULL; n = n->next) {
		if (n->module == r->m && (n->flags & SNF_INTERNAL) == 0) {
			buf_puts(b, "| `");
			{
				struct buf p;

				buf_init(&p);
				path(&p, n);
				cell(b, p.p);
				buf_free(&p);
			}
			buf_printf(b, "` | %s", snode_kind_name(n->kind));
			for (size_t i = 0; i < n->nkeys; i++)
				buf_printf(b, "%s%s%s", i == 0 ? " [" : " ",
				    n->keys[i]->name, i + 1 == n->nkeys ?
				    "]" : "");
			buf_printf(b, "%s | ", (n->flags & SNF_OBSOLETE) != 0 ?
			    " (obsolete)" : (n->flags & SNF_DEPRECATED) != 0 ?
			    " (deprecated)" : "");
			type(b, n);
			buf_printf(b, " | %s | ", in_operation(n) ||
			    n->in != NULL ? "" : (n->flags & SNF_CONFIG) != 0 ?
			    "true" : "false");
			mandatory(b, n);
			buf_puts(b, " | ");
			for (size_t i = 0; i < n->ndflts; i++) {
				buf_puts(b, i > 0 ? ", " : "");
				code(b, n->dflts[i]);
			}
			if (n->dflt_case != NULL)
				code(b, n->dflt_case->name);
			buf_puts(b, " | ");
			if (n->units != NULL)
				cell(b, n->units);
			buf_puts(b, " |");
			if (r->sids && n->sid != 0)
				buf_printf(b, " %" PRIu64 " |", n->sid);
			else if (r->sids)
				buf_puts(b, " |");
			buf_puts(b, "\n");
		}
		row(n->child, r);
	}
}

/*
 * The nodes m defines in mm's trees and structures, and a structure or
 * yang-data of m's itself.
 */
static void
rows_of(const struct smodule *mm, struct rows *r)
{
	const struct sext *e;

	row(mm->data, r);
	row(mm->rpcs, r);
	row(mm->notifs, r);
	for (size_t i = 0; i < mm->nexts; i++) {
		e = &mm->exts[i];
		if (e->data != NULL && e->module == r->m && e->arg != NULL) {
			buf_printf(r->b, "| `/%s:", e->module->name);
			cell(r->b, e->arg);
			buf_printf(r->b, "` | %s |  |  |  |  |  |",
			    strchr(e->ext, ':') + 1);
			if (r->sids && e->sid != 0)
				buf_printf(r->b, " %" PRIu64 " |", e->sid);
			else if (r->sids)
				buf_puts(r->b, " |");
			buf_puts(r->b, "\n");
		}
		row(e->data, r);
	}
}

static void
identities(const struct schema *s, const struct smodule *m, struct buf *b,
    bool sids)
{

	buf_printf(b, "## Identities\n\n| Identity | Based on |%s\n"
	    "|---|---|%s\n", sids ? " SID |" : "", sids ? "---:|" : "");
	for (size_t i = 0; i < m->nidents; i++) {
		const struct sident *id = &m->idents[i];
		bool first = true;

		buf_printf(b, "| `%s`%s | ", id->name,
		    (id->flags & SNF_OBSOLETE) != 0 ? " (obsolete)" :
		    (id->flags & SNF_DEPRECATED) != 0 ? " (deprecated)" : "");
		/* Its bases: the identities it is derived from directly. */
		for (size_t j = 0; j < s->nmods; j++)
			for (size_t k = 0; k < s->mods[j]->nidents; k++) {
				const struct sident *base =
				    &s->mods[j]->idents[k];

				for (size_t l = 0; l < base->nderived; l++) {
					if (base->derived[l] != id)
						continue;
					buf_printf(b, "%s`%s:%s`", first ? "" :
					    ", ", base->module->name,
					    base->name);
					first = false;
				}
			}
		buf_puts(b, " |");
		if (sids && id->sid != 0)
			buf_printf(b, " %" PRIu64 " |", id->sid);
		else if (sids)
			buf_puts(b, " |");
		buf_puts(b, "\n");
	}
	buf_puts(b, "\n");
}

static void
module_md(const struct schema *s, const struct smodule *m, struct buf *b)
{
	struct rows r = { .b = b, .m = m, .sids = m->sid != 0 };

	buf_printf(b, "# Module `%s`\n\n| | |\n|---|---|\n", m->name);
	if (m->revision != NULL)
		buf_printf(b, "| Revision | %s |\n", m->revision);
	buf_printf(b, "| Namespace | `%s` |\n| Prefix | `%s` |\n", m->ns,
	    m->prefix);
	if (r.sids)
		buf_printf(b, "| SID | %" PRIu64 " |\n", m->sid);
	if (m->ndeviated_by > 0) {
		buf_puts(b, "| Deviated by | ");
		for (size_t i = 0; i < m->ndeviated_by; i++)
			buf_printf(b, "%s`%s`", i > 0 ? ", " : "",
			    m->deviated_by[i]);
		buf_puts(b, " |\n");
	}

	buf_puts(b, "\n## Tree diagram\n\n```\n");
	gen_yang_tree_module(m, b);
	buf_puts(b, "```\n\n");

	buf_printf(b, "## Nodes\n\n| Node | Kind | Type | Config | "
	    "Mandatory | Default | Units |%s\n|---|---|---|---|---|---|---|"
	    "%s\n", r.sids ? " SID |" : "", r.sids ? "---:|" : "");
	rows_of(m, &r);
	for (size_t i = 0; i < s->nmods; i++)
		if (s->mods[i] != m && s->mods[i]->implemented)
			rows_of(s->mods[i], &r);
	buf_puts(b, "\n");

	if (m->nfeatures > 0) {
		buf_printf(b, "## Features\n\n| Feature | Enabled |%s\n"
		    "|---|---|%s\n", r.sids ? " SID |" : "",
		    r.sids ? "---:|" : "");
		for (size_t i = 0; i < m->nfeatures; i++) {
			buf_printf(b, "| `%s` | %s |", m->features[i].name,
			    m->features[i].enabled ? "yes" : "no");
			if (r.sids && m->features[i].sid != 0)
				buf_printf(b, " %" PRIu64 " |",
				    m->features[i].sid);
			else if (r.sids)
				buf_puts(b, " |");
			buf_puts(b, "\n");
		}
		buf_puts(b, "\n");
	}
	if (m->nidents > 0)
		identities(s, m, b, r.sids);
}

void
gen_yang_md(const struct schema *s, const char *from, struct buf *b)
{

	buf_printf(b, "<!-- Generated by cblink-gen %s from %s. Do not edit. "
	    "-->\n\n", CBLGEN_VERSION, from);
	for (size_t i = 0; i < s->nmods; i++)
		if (s->mods[i]->given && s->mods[i]->implemented)
			module_md(s, s->mods[i], b);
}
