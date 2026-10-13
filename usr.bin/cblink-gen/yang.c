/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The YANG front end: libyang 3 parses and compiles the modules (Arcana's
 * PLAN-SDN-YANG, decision D-3).  cblink-gen reads untrusted input in
 * capability mode, where libyang cannot open the files a module imports,
 * so every module the generator may need is read into memory first, from
 * the search directories, and libyang is given them through its import
 * callback; the context is made before capability mode too, while
 * libyang can still load its plugins.
 */

#include <sys/stat.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "gen.h"
#include "schema.h"
#include "yang.h"

/* A module's text, by the name and revision its file name gives. */
struct ysrc {
	char	*name;
	char	*rev;		/* NULL: the file name has none */
	char	*text;
	char	*file;		/* for diagnostics */
	bool	 given;		/* named by the user, not only found */
};

static struct ysrc	*srcs;
static size_t		 nsrcs;
static struct diags	*logto;		/* libyang's messages, while parsing */

static char *
read_all(int fd, const char *path)
{
	struct stat sb;
	size_t len = 0;
	ssize_t n;
	char *data;

	if (fstat(fd, &sb) != 0)
		err(2, "%s", path);
	if (!S_ISREG(sb.st_mode))
		errx(2, "%s: not a regular file", path);
	if (sb.st_size > YANG_MAX_FILE)
		errx(1, "%s: file too large (limit %d bytes)", path,
		    YANG_MAX_FILE);
	data = xcalloc((size_t)sb.st_size + 1, 1);
	while (len < (size_t)sb.st_size &&
	    (n = read(fd, data + len, (size_t)sb.st_size - len)) > 0)
		len += (size_t)n;
	if (len != (size_t)sb.st_size)
		errx(2, "%s: short read", path);
	return (data);
}

/* "name@rev.yang" or "name.yang"; anything else is not a module file. */
static bool
split_name(const char *file, char **namep, char **revp)
{
	const char *at, *dot;

	if ((dot = strrchr(file, '.')) == NULL || strcmp(dot, ".yang") != 0 ||
	    dot == file)
		return (false);
	if ((at = memchr(file, '@', (size_t)(dot - file))) != NULL) {
		*namep = xstrndup(file, (size_t)(at - file));
		*revp = xstrndup(at + 1, (size_t)(dot - at - 1));
	} else {
		*namep = xstrndup(file, (size_t)(dot - file));
		*revp = NULL;
	}
	return (true);
}

void
yang_add_file(int fd, const char *path, bool given)
{
	const char *file;
	struct ysrc *s;
	char *name, *rev;

	file = (file = strrchr(path, '/')) != NULL ? file + 1 : path;
	if (!split_name(file, &name, &rev))
		errx(2, "%s: not a YANG module file (name.yang or "
		    "name@revision.yang)", path);
	srcs = xreallocarray(srcs, nsrcs + 1, sizeof(*srcs));
	s = &srcs[nsrcs++];
	s->name = name;
	s->rev = rev;
	s->text = read_all(fd, path);
	s->file = xstrdup(file);
	s->given = given;
}

void
yang_add_dir(const char *dir)
{
	struct dirent *de;
	DIR *d;
	char *path, *name, *rev;
	int fd;

	if ((d = opendir(dir)) == NULL)
		err(2, "%s", dir);
	while ((de = readdir(d)) != NULL) {
		if (!split_name(de->d_name, &name, &rev))
			continue;
		free(name);
		free(rev);
		path = xasprintf("%s/%s", dir, de->d_name);
		if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1)
			err(2, "%s", path);
		yang_add_file(fd, path, false);
		close(fd);
		free(path);
	}
	closedir(d);
}

/* The text of a module: the revision asked for, or the latest. */
static const char *
find(const char *name, const char *rev)
{
	const struct ysrc *best = NULL;

	for (size_t i = 0; i < nsrcs; i++) {
		if (strcmp(srcs[i].name, name) != 0)
			continue;
		if (rev != NULL) {
			if (srcs[i].rev != NULL && strcmp(srcs[i].rev, rev) == 0)
				return (srcs[i].text);
			continue;
		}
		if (best == NULL || (srcs[i].rev != NULL && (best->rev == NULL ||
		    strcmp(srcs[i].rev, best->rev) > 0)))
			best = &srcs[i];
	}
	return (best != NULL ? best->text : NULL);
}

static LY_ERR
imp(const char *mod, const char *mod_rev, const char *sub,
    const char *sub_rev, void *arg __unused, LYS_INFORMAT *format,
    const char **data, ly_module_imp_data_free_clb *free_data)
{
	const char *text;

	text = sub != NULL ? find(sub, sub_rev) : find(mod, mod_rev);
	if (text == NULL)
		return (LY_ENOTFOUND);
	*format = LYS_IN_YANG;
	*data = text;
	*free_data = NULL;
	return (LY_SUCCESS);
}

static void
log_clb(LY_LOG_LEVEL level, const char *msg, const char *data_path __unused,
    const char *schema_path, uint64_t line)
{

	if (logto == NULL || level != LY_LLERR)
		return;
	if (schema_path != NULL)
		diag_add(logto, (int)line, 0, "%s (%s)", msg, schema_path);
	else
		diag_add(logto, (int)line, 0, "%s", msg);
}

struct ly_ctx *
yang_ctx_new(void)
{
	struct ly_ctx *ctx;

	ly_set_log_clb(log_clb);
	if (ly_ctx_new(NULL, LY_CTX_DISABLE_SEARCHDIRS | LY_CTX_REF_IMPLEMENTED,
	    &ctx) != LY_SUCCESS)
		errx(2, "libyang: cannot make a context");
	ly_ctx_set_module_imp_clb(ctx, imp, NULL);
	return (ctx);
}

/*
 * Parse and compile the modules named, their imports from the others.
 * d->file is set to each module's file while it is parsed.
 */
int
yang_load(struct ly_ctx *ctx, struct diags *d, const char **features)
{
	struct lys_module *mod;
	struct ly_in *in;
	int rv = 0;
	LY_ERR e;

	for (size_t i = 0; i < nsrcs; i++) {
		if (!srcs[i].given)
			continue;
		d->file = srcs[i].file;
		if (ly_in_new_memory(srcs[i].text, &in) != LY_SUCCESS)
			errx(2, "libyang: no memory");
		logto = d;
		e = lys_parse(ctx, in, LYS_IN_YANG, features, &mod);
		logto = NULL;
		ly_in_free(in, 0);
		if (e != LY_SUCCESS) {
			if (d->n == 0)
				diag_add(d, 0, 0, "the module does not compile");
			return (-1);
		}
	}
	return (rv);
}

/*
 * From libyang's compiled schema to the generator's own (schema.h).
 */

struct conv {
	struct schema		 *s;
	const struct lys_module **lmods;	/* parallel to s->mods */
};

static struct smodule *
smod_of(struct conv *c, const struct lys_module *lm)
{

	for (size_t i = 0; i < c->s->nmods; i++)
		if (c->lmods[i] == lm)
			return (c->s->mods[i]);
	errx(2, "libyang: a node of a module not in the context");
}

static enum snode_kind
kind_of(uint16_t nodetype)
{

	switch (nodetype) {
	case LYS_CONTAINER:	return (SN_CONTAINER);
	case LYS_LEAF:		return (SN_LEAF);
	case LYS_LEAFLIST:	return (SN_LEAFLIST);
	case LYS_LIST:		return (SN_LIST);
	case LYS_CHOICE:	return (SN_CHOICE);
	case LYS_CASE:		return (SN_CASE);
	case LYS_ANYDATA:	return (SN_ANYDATA);
	case LYS_ANYXML:	return (SN_ANYXML);
	case LYS_RPC:		return (SN_RPC);
	case LYS_ACTION:	return (SN_ACTION);
	case LYS_NOTIF:		return (SN_NOTIF);
	case LYS_INPUT:		return (SN_INPUT);
	case LYS_OUTPUT:	return (SN_OUTPUT);
	}
	errx(2, "libyang: a schema node of unknown kind %#x", nodetype);
}

static struct snode *conv_list(struct conv *, const struct lysc_node *,
    struct snode *);

static struct snode *
conv_node(struct conv *c, const struct lysc_node *ln, struct snode *parent)
{
	struct snode *n, **tail;
	const struct lysc_node_action *a;
	const struct lysc_node_notif *no;

	n = xcalloc(1, sizeof(*n));
	n->kind = kind_of(ln->nodetype);
	n->name = xstrdup(ln->name);
	n->module = smod_of(c, ln->module);
	n->parent = parent;
	if ((ln->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF | LYS_INPUT |
	    LYS_OUTPUT)) == 0 && (ln->flags & LYS_CONFIG_W) != 0)
		n->flags |= SNF_CONFIG;
	if ((ln->flags & LYS_MAND_TRUE) != 0)
		n->flags |= SNF_MANDATORY;
	if (ln->nodetype == LYS_LEAF && (ln->flags & LYS_KEY) != 0)
		n->flags |= SNF_KEY;
	if (ln->nodetype == LYS_CONTAINER && (ln->flags & LYS_PRESENCE) != 0)
		n->flags |= SNF_PRESENCE;
	if (lysc_is_userordered(ln))
		n->flags |= SNF_USERORDER;
	if ((ln->flags & LYS_STATUS_DEPRC) != 0)
		n->flags |= SNF_DEPRECATED;
	if ((ln->flags & LYS_STATUS_OBSLT) != 0)
		n->flags |= SNF_OBSOLETE;
	if (ln->nodetype == LYS_LIST) {
		const struct lysc_node_list *l = (const void *)ln;

		n->min = l->min;
		n->max = l->max;
	} else if (ln->nodetype == LYS_LEAFLIST) {
		const struct lysc_node_leaflist *l = (const void *)ln;

		n->min = l->min;
		n->max = l->max;
	}

	/* Data children, then actions, then notifications. */
	n->child = conv_list(c, lysc_node_child(ln), n);
	for (tail = &n->child; *tail != NULL; tail = &(*tail)->next)
		;
	for (a = lysc_node_actions(ln); a != NULL;
	    a = (const struct lysc_node_action *)a->next) {
		*tail = conv_node(c, &a->node, n);
		tail = &(*tail)->next;
	}
	for (no = lysc_node_notifs(ln); no != NULL;
	    no = (const struct lysc_node_notif *)no->next) {
		*tail = conv_node(c, &no->node, n);
		tail = &(*tail)->next;
	}

	if (n->kind == SN_LIST) {
		for (struct snode *ch = n->child; ch != NULL; ch = ch->next)
			if ((ch->flags & SNF_KEY) != 0) {
				n->keys = xreallocarray(n->keys, n->nkeys + 1,
				    sizeof(*n->keys));
				n->keys[n->nkeys++] = ch;
			}
	}
	return (n);
}

static struct snode *
conv_list(struct conv *c, const struct lysc_node *ln, struct snode *parent)
{
	struct snode *first = NULL, **tail = &first;

	for (; ln != NULL; ln = ln->next) {
		*tail = conv_node(c, ln, parent);
		tail = &(*tail)->next;
	}
	return (first);
}

struct schema *
yang_schema(struct ly_ctx *ctx)
{
	struct conv c = { 0 };
	const struct lys_module *lm;
	const struct lysp_feature *f;
	struct smodule *m;
	struct sident *si;
	LY_ARRAY_COUNT_TYPE u, v;
	uint32_t idx = 0, fi;
	size_t i;

	c.s = schema_new();
	/* Every module, implemented or only imported: identities. */
	while ((lm = ly_ctx_get_module_iter(ctx, &idx)) != NULL) {
		m = xcalloc(1, sizeof(*m));
		m->name = xstrdup(lm->name);
		m->revision = lm->revision != NULL ? xstrdup(lm->revision) :
		    NULL;
		m->ns = xstrdup(lm->ns);
		m->prefix = xstrdup(lm->prefix);
		m->implemented = lm->implemented && lm->compiled != NULL;
		c.s->mods = xreallocarray(c.s->mods, c.s->nmods + 1,
		    sizeof(*c.s->mods));
		c.lmods = xreallocarray(c.lmods, c.s->nmods + 1,
		    sizeof(*c.lmods));
		c.s->mods[c.s->nmods] = m;
		c.lmods[c.s->nmods++] = lm;
		fi = 0;
		f = NULL;
		while (lm->parsed != NULL &&
		    (f = lysp_feature_next(f, lm->parsed, &fi)) != NULL) {
			m->features = xreallocarray(m->features,
			    m->nfeatures + 1, sizeof(*m->features));
			m->features[m->nfeatures].name = xstrdup(f->name);
			m->features[m->nfeatures++].enabled =
			    (f->flags & LYS_FENABLED) != 0;
		}
		m->nidents = LY_ARRAY_COUNT(lm->identities);
		m->idents = xcalloc(m->nidents, sizeof(*m->idents));
		LY_ARRAY_FOR(lm->identities, u) {
			m->idents[u].module = m;
			m->idents[u].name = xstrdup(lm->identities[u].name);
			if ((lm->identities[u].flags & LYS_STATUS_DEPRC) != 0)
				m->idents[u].flags |= SNF_DEPRECATED;
			if ((lm->identities[u].flags & LYS_STATUS_OBSLT) != 0)
				m->idents[u].flags |= SNF_OBSOLETE;
		}
		LY_ARRAY_FOR(lm->deviated_by, u) {
			m->deviated_by = xreallocarray(m->deviated_by,
			    m->ndeviated_by + 1, sizeof(*m->deviated_by));
			m->deviated_by[m->ndeviated_by++] =
			    xstrdup(lm->deviated_by[u]->name);
		}
	}
	/* Derived identities, now that every module has its own. */
	for (i = 0; i < c.s->nmods; i++) {
		lm = c.lmods[i];
		LY_ARRAY_FOR(lm->identities, u) {
			si = &c.s->mods[i]->idents[u];
			LY_ARRAY_FOR(lm->identities[u].derived, v) {
				const struct lysc_ident *d =
				    lm->identities[u].derived[v];
				struct sident *ds;

				ds = schema_ident(c.s, d->module->name, d->name);
				if (ds == NULL)
					continue;	/* of a module not loaded */
				si->derived = xreallocarray(si->derived,
				    si->nderived + 1, sizeof(*si->derived));
				si->derived[si->nderived++] = ds;
			}
		}
	}
	/* The data trees of the implemented modules. */
	for (i = 0; i < c.s->nmods; i++) {
		lm = c.lmods[i];
		if (!c.s->mods[i]->implemented)
			continue;
		c.s->mods[i]->data = conv_list(&c, lm->compiled->data, NULL);
		c.s->mods[i]->rpcs = conv_list(&c,
		    lm->compiled->rpcs != NULL ? &lm->compiled->rpcs->node :
		    NULL, NULL);
		c.s->mods[i]->notifs = conv_list(&c,
		    lm->compiled->notifs != NULL ? &lm->compiled->notifs->node :
		    NULL, NULL);
	}
	free(c.lmods);
	return (c.s);
}
