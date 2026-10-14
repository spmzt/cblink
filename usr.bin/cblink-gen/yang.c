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
#include <libyang/plugins_exts.h>

#include "cbl_xpath.h"
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

/*
 * The context, before capability mode.  libyang has some modules built
 * in (ietf-yang-types, ietf-inet-types and others) and loads them now,
 * resolving their imports from the search directories it is given here:
 * so that an import without a revision takes the latest revision there,
 * as the modules' own imports will, the directories are given, and only
 * then is searching turned off, so that libyang never opens a file in
 * capability mode.  Everything else comes through the import callback.
 */
struct ly_ctx *
yang_ctx_new(const char **dirs, size_t ndirs)
{
	struct ly_ctx *ctx;
	struct buf b;

	buf_init(&b);
	for (size_t i = 0; i < ndirs; i++) {
		if (strchr(dirs[i], ':') != NULL)
			errx(2, "%s: a search directory with ':' in its "
			    "name", dirs[i]);
		buf_printf(&b, "%s%s", i > 0 ? ":" : "", dirs[i]);
	}
	ly_set_log_clb(log_clb);
	/*
	 * Each compiled node keeps its parsed node in its priv, for what is
	 * only written there and the tree diagrams show: its if-features
	 * and its type as written.
	 */
	if (ly_ctx_new(ndirs > 0 ? b.p : NULL, LY_CTX_DISABLE_SEARCHDIR_CWD |
	    LY_CTX_REF_IMPLEMENTED | LY_CTX_SET_PRIV_PARSED, &ctx) !=
	    LY_SUCCESS)
		errx(2, "libyang: cannot make a context");
	buf_free(&b);
	if (ly_ctx_set_options(ctx, LY_CTX_DISABLE_SEARCHDIRS) != LY_SUCCESS)
		errx(2, "libyang: cannot turn searching off");
	ly_ctx_set_module_imp_clb(ctx, imp, NULL);
	return (ctx);
}

/*
 * Parse and compile the modules named, their imports from the others;
 * then set the features of every implemented module as yanglint's -F
 * does: with no spec, all of them on; with specs ("module:f1,f2", or
 * "module:" for none, "module:*" for all), each module's as its spec
 * says and those of modules named in no spec off.  libyang then applies
 * the deviations of the modules loaded and leaves out what a disabled
 * feature guards.
 */
static int
load(struct ly_ctx *ctx, struct diags *d, const char **specs,
    size_t nspecs, const char *only, const char *onlyrev)
{
	const char *all[] = { "*", NULL }, *none[] = { NULL };
	struct lys_module *mod, **impl = NULL;
	struct ly_in *in;
	const char *file;
	size_t nimpl = 0, nparsed = 0;
	uint32_t idx = 0;
	LY_ERR e;

	for (size_t i = 0; i < nsrcs; i++) {
		const char *text = srcs[i].text;

		/* Alone: its text as an import would find it, given or not. */
		if (only != NULL) {
			if (nparsed > 0 || (text = find(only, onlyrev)) == NULL)
				break;
		} else if (!srcs[i].given)
			continue;
		nparsed++;
		d->file = only != NULL ? only : srcs[i].file;
		if (ly_in_new_memory(text, &in) != LY_SUCCESS)
			errx(2, "libyang: no memory");
		logto = d;
		e = lys_parse(ctx, in, LYS_IN_YANG, NULL, &mod);
		logto = NULL;
		ly_in_free(in, 0);
		if (e != LY_SUCCESS) {
			if (d->n == 0)
				diag_add(d, 0, 0, "the module does not compile");
			return (-1);
		}
	}

	if (only != NULL && nparsed == 0)
		return (1);
	file = d->file;
	d->file = "-F";
	for (size_t i = 0; i < nspecs; i++) {
		const char *colon = strchr(specs[i], ':');
		char *name;

		if (colon == NULL || colon == specs[i]) {
			diag_add(d, 0, 0, "'%s': expected module:feature,...",
			    specs[i]);
			return (-1);
		}
		name = xstrndup(specs[i], (size_t)(colon - specs[i]));
		mod = ly_ctx_get_module_implemented(ctx, name);
		if (mod == NULL)
			diag_add(d, 0, 0, "'%s': no module %s implemented",
			    specs[i], name);
		free(name);
		if (mod == NULL)
			return (-1);
	}
	while ((mod = ly_ctx_get_module_iter(ctx, &idx)) != NULL)
		if (mod->implemented) {
			impl = xreallocarray(impl, nimpl + 1, sizeof(*impl));
			impl[nimpl++] = mod;
		}
	for (size_t i = 0; i < nimpl; i++) {
		const char **feats = nspecs == 0 ? all : none;
		const char **list = NULL;
		size_t nlist = 0;

		/* The features of the module's specs, together. */
		for (size_t j = 0; j < nspecs; j++) {
			size_t len = strlen(impl[i]->name);
			char *dup, *f, *p;

			if (strncmp(specs[j], impl[i]->name, len) != 0 ||
			    specs[j][len] != ':')
				continue;
			dup = xstrdup(specs[j] + len + 1);
			for (p = dup; (f = strsep(&p, ",")) != NULL;) {
				if (*f == '\0')
					continue;
				list = xreallocarray(list, nlist + 2,
				    sizeof(*list));
				list[nlist++] = xstrdup(f);
				list[nlist] = NULL;
			}
			free(dup);
		}
		if (list != NULL)
			feats = list;
		/* Every module has its features set: none is not "as before". */
		if (feats == none && impl[i]->parsed != NULL &&
		    impl[i]->parsed->features == NULL)
			continue;
		logto = d;
		e = lys_set_implemented(impl[i], feats);
		logto = NULL;
		for (size_t j = 0; j < nlist; j++)
			free(__DECONST(char *, list[j]));
		free(list);
		if (e != LY_SUCCESS) {
			if (d->n == 0)
				diag_add(d, 0, 0, "%s: its features cannot be "
				    "set", impl[i]->name);
			free(impl);
			return (-1);
		}
	}
	free(impl);
	d->file = file;
	return (0);
}

int
yang_load(struct ly_ctx *ctx, struct diags *d, const char **specs,
    size_t nspecs)
{

	return (load(ctx, d, specs, nspecs, NULL, NULL));
}

int
yang_load_one(struct ly_ctx *ctx, struct diags *d, const char *name,
    const char *rev)
{

	return (load(ctx, d, NULL, 0, name, rev));
}

/*
 * From libyang's compiled schema to the generator's own (schema.h).
 */

struct conv {
	struct schema		 *s;
	const struct ly_ctx	 *ctx;
	const struct lys_module **lmods;	/* parallel to s->mods */
	struct sext		 *in;		/* the instance being walked */
	const char		 *cur;		/* the node's module, while made */
};

/* A prefix of an expression, by libyang's map of them: its module. */
static const char *
prefix_module(const struct lysc_prefix *prefixes, const char *prefix)
{
	/* A sized array: its count before it, read without libyang's
	 * macro, which drops const. */
	LY_ARRAY_COUNT_TYPE n = prefixes != NULL ?
	    ((const LY_ARRAY_COUNT_TYPE *)(const void *)prefixes)[-1] : 0;

	for (LY_ARRAY_COUNT_TYPE u = 0; u < n; u++)
		if (prefixes[u].prefix != NULL &&
		    strcmp(prefixes[u].prefix, prefix) == 0)
			return (prefixes[u].mod->name);
	return (NULL);
}

static void
canon_walk(struct cbl_xp *x, const struct lysc_prefix *prefixes,
    const char *cur)
{
	const char *m;

	if (x == NULL)
		return;
	/* A name test: its module's name for its prefix; none, the node's
	 * (RFC 7950 section 6.4.1).  "*" alone stays any module's. */
	if (x->kind == CBL_XP_STEP && (x->test == CBL_XT_NAME ||
	    (x->test == CBL_XT_ANY && x->prefix != NULL))) {
		m = x->prefix != NULL ? prefix_module(prefixes, x->prefix) : cur;
		if (m != NULL) {
			free(x->prefix);
			x->prefix = xstrdup(m);
		}
	}
	/* A literal "prefix:name" whose prefix is one of the module's: an
	 * identity's name, compared with an identityref, which the tables
	 * give as "module:name". */
	if (x->kind == CBL_XP_LITERAL && x->s != NULL &&
	    strchr(x->s, ':') != NULL) {
		char *colon = strchr(x->s, ':'), *nl;

		*colon = '\0';
		m = prefix_module(prefixes, x->s);
		*colon = ':';
		if (m != NULL) {
			nl = xasprintf("%s:%s", m, colon + 1);
			free(x->s);
			x->s = nl;
		}
	}
	/* derived-from()'s identity, a literal "prefix:name". */
	if (x->kind == CBL_XP_FUNC && x->nargs == 2 &&
	    (strcmp(x->s, "derived-from") == 0 ||
	    strcmp(x->s, "derived-from-or-self") == 0) &&
	    x->args[1]->kind == CBL_XP_LITERAL) {
		char *lit = x->args[1]->s, *colon = strchr(lit, ':'), *nl;

		if (colon != NULL) {
			*colon = '\0';
			m = prefix_module(prefixes, lit);
			*colon = ':';
		} else
			m = cur;
		if (m != NULL) {
			nl = xasprintf("%s:%s", m, colon != NULL ? colon + 1 :
			    lit);
			free(x->args[1]->s);
			x->args[1]->s = nl;
		}
	}
	for (size_t i = 0; i < x->nargs; i++)
		canon_walk(x->args[i], prefixes, cur);
	for (size_t i = 0; i < x->npreds; i++)
		canon_walk(x->preds[i], prefixes, cur);
	canon_walk(x->base, prefixes, cur);
}

/*
 * An expression with its names by module, not by the prefixes of the
 * module that wrote it, which the tables cannot resolve: printed again,
 * each step with its axis.  One that does not parse is kept as written,
 * for the profile check to refuse.
 */
static char *
xp_canon(const char *expr, const struct lysc_prefix *prefixes,
    const char *cur)
{
	struct cbl_xp *x;
	char why[128], *out = NULL;
	size_t pos, len;
	FILE *fp;

	if ((x = cbl_xp_parse(expr, why, sizeof(why), &pos)) == NULL)
		return (xstrdup(expr));
	canon_walk(x, prefixes, cur);
	if ((fp = open_memstream(&out, &len)) == NULL)
		err(2, "open_memstream");
	cbl_xp_print(x, fp);
	fclose(fp);
	cbl_xp_free(x);
	return (out);
}

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

static char *
xstrdup_or_null(const char *p)
{

	return (p != NULL ? xstrdup(p) : NULL);
}

static char **
conv_iffeatures(struct lysp_qname *q, size_t *np)
{
	char **v;
	LY_ARRAY_COUNT_TYPE u;

	*np = LY_ARRAY_COUNT(q);
	v = xcalloc(*np, sizeof(*v));
	LY_ARRAY_FOR(q, u)
		v[u] = xstrdup(q[u].str);
	return (v);
}

/* A leaf's or leaf-list's type statement: its argument, a path given. */
static void
conv_wtype(const struct lysp_node *pn, char **typep, char **pathp)
{
	const void *v = pn;
	const struct lysp_type *t;

	if (pn->nodetype == LYS_LEAF)
		t = &((const struct lysp_node_leaf *)v)->type;
	else if (pn->nodetype == LYS_LEAFLIST)
		t = &((const struct lysp_node_leaflist *)v)->type;
	else
		return;
	*typep = xstrdup_or_null(t->name);
	*pathp = t->path != NULL ? xstrdup(lyxp_get_expr(t->path)) : NULL;
}

static struct swnode *conv_wlist(const struct lysp_node *, struct swnode *);

/* The children of a node or an augment: data, actions, notifications. */
static struct swnode *
conv_wchildren(const struct lysp_node *pn, struct swnode *parent)
{
	const struct lysp_node_action *a;
	const struct lysp_node_notif *no;
	struct swnode *first, **tail;

	first = conv_wlist(lysp_node_child(pn), parent);
	for (tail = &first; *tail != NULL; tail = &(*tail)->next)
		;
	if ((a = lysp_node_actions(pn)) != NULL)
		*tail = conv_wlist(&a->node, parent);
	for (; *tail != NULL; tail = &(*tail)->next)
		;
	if ((no = lysp_node_notifs(pn)) != NULL)
		*tail = conv_wlist(&no->node, parent);
	return (first);
}

/*
 * A node as written.  An action's or rpc's children are its input and its
 * output, always both, as in the compiled model.
 */
static struct swnode *
conv_wnode(const struct lysp_node *pn, struct swnode *parent)
{
	const struct lysp_node_action *a;
	struct swnode *n;

	n = xcalloc(1, sizeof(*n));
	n->parent = parent;
	n->name = xstrdup(pn->name);
	if (pn->nodetype == LYS_USES)
		n->uses = true;
	else
		n->kind = kind_of(pn->nodetype);
	if ((pn->flags & LYS_CONFIG_W) != 0)
		n->flags |= SNF_CONFIG;
	if ((pn->flags & LYS_CONFIG_R) != 0)
		n->flags |= SNF_STATE;
	if ((pn->flags & LYS_STATUS_CURR) != 0)
		n->flags |= SNF_CURRENT;
	if ((pn->flags & LYS_STATUS_DEPRC) != 0)
		n->flags |= SNF_DEPRECATED;
	if ((pn->flags & LYS_STATUS_OBSLT) != 0)
		n->flags |= SNF_OBSOLETE;
	if ((pn->flags & LYS_MAND_TRUE) != 0)
		n->flags |= SNF_MANDATORY;
	if (pn->nodetype == LYS_CONTAINER && ((const struct
	    lysp_node_container *)(const void *)pn)->presence != NULL)
		n->flags |= SNF_PRESENCE;
	if (pn->nodetype == LYS_LIST)
		n->key = xstrdup_or_null(((const struct lysp_node_list *)
		    (const void *)pn)->key);
	conv_wtype(pn, &n->type, &n->path);
	n->iffeatures = conv_iffeatures(pn->iffeatures, &n->niffeatures);

	if ((pn->nodetype & (LYS_RPC | LYS_ACTION)) != 0) {
		a = (const struct lysp_node_action *)(const void *)pn;
		n->child = conv_wnode(&a->input.node, n);
		n->child->next = conv_wnode(&a->output.node, n);
		return (n);
	}
	n->child = conv_wchildren(pn, n);
	return (n);
}

static struct swnode *
conv_wlist(const struct lysp_node *pn, struct swnode *parent)
{
	struct swnode *first = NULL, **tail = &first;

	for (; pn != NULL; pn = pn->next) {
		*tail = conv_wnode(pn, parent);
		tail = &(*tail)->next;
	}
	return (first);
}

static enum sntype_base
base_of(LY_DATA_TYPE t)
{

	switch (t) {
	case LY_TYPE_BINARY:	return (ST_BINARY);
	case LY_TYPE_UINT8:	return (ST_UINT8);
	case LY_TYPE_UINT16:	return (ST_UINT16);
	case LY_TYPE_UINT32:	return (ST_UINT32);
	case LY_TYPE_UINT64:	return (ST_UINT64);
	case LY_TYPE_STRING:	return (ST_STRING);
	case LY_TYPE_BITS:	return (ST_BITS);
	case LY_TYPE_BOOL:	return (ST_BOOLEAN);
	case LY_TYPE_DEC64:	return (ST_DECIMAL64);
	case LY_TYPE_EMPTY:	return (ST_EMPTY);
	case LY_TYPE_ENUM:	return (ST_ENUMERATION);
	case LY_TYPE_IDENT:	return (ST_IDENTITYREF);
	case LY_TYPE_INST:	return (ST_INSTANCEID);
	case LY_TYPE_LEAFREF:	return (ST_LEAFREF);
	case LY_TYPE_UNION:	return (ST_UNION);
	case LY_TYPE_INT8:	return (ST_INT8);
	case LY_TYPE_INT16:	return (ST_INT16);
	case LY_TYPE_INT32:	return (ST_INT32);
	case LY_TYPE_INT64:	return (ST_INT64);
	default:
		break;
	}
	errx(2, "libyang: a type of unknown base %d", (int)t);
}

static struct srange *
conv_range(const struct lysc_range *lr, bool sgn)
{
	struct srange *r;
	LY_ARRAY_COUNT_TYPE u;

	if (lr == NULL)
		return (NULL);
	r = xcalloc(1, sizeof(*r));
	r->nparts = LY_ARRAY_COUNT(lr->parts);
	r->parts = xcalloc(r->nparts, sizeof(*r->parts));
	LY_ARRAY_FOR(lr->parts, u) {
		if (sgn) {
			r->parts[u].min.i = lr->parts[u].min_64;
			r->parts[u].max.i = lr->parts[u].max_64;
		} else {
			r->parts[u].min.u = lr->parts[u].min_u64;
			r->parts[u].max.u = lr->parts[u].max_u64;
		}
	}
	r->emsg = xstrdup_or_null(lr->emsg);
	r->eapptag = xstrdup_or_null(lr->eapptag);
	return (r);
}

static struct sntype *
conv_type(struct conv *c, const struct lysc_type *lt)
{
	const struct lysc_type_num *num = (const void *)lt;
	const struct lysc_type_dec *dec = (const void *)lt;
	const struct lysc_type_str *str = (const void *)lt;
	const struct lysc_type_bin *bin = (const void *)lt;
	const struct lysc_type_enum *en = (const void *)lt;
	const struct lysc_type_bits *bits = (const void *)lt;
	const struct lysc_type_identityref *idr = (const void *)lt;
	const struct lysc_type_leafref *lr = (const void *)lt;
	const struct lysc_type_instanceid *ii = (const void *)lt;
	const struct lysc_type_union *un = (const void *)lt;
	struct lysc_type_bitenum_item *items = NULL;
	struct sntype *t;
	LY_ARRAY_COUNT_TYPE u;

	t = xcalloc(1, sizeof(*t));
	t->base = base_of(lt->basetype);
	t->name = xstrdup_or_null(lt->name);
	switch (t->base) {
	case ST_INT8: case ST_INT16: case ST_INT32: case ST_INT64:
		t->range = conv_range(num->range, true);
		break;
	case ST_UINT8: case ST_UINT16: case ST_UINT32: case ST_UINT64:
		t->range = conv_range(num->range, false);
		break;
	case ST_DECIMAL64:
		t->fdigits = dec->fraction_digits;
		t->range = conv_range(dec->range, true);
		break;
	case ST_STRING:
		t->length = conv_range(str->length, false);
		t->npatterns = LY_ARRAY_COUNT(str->patterns);
		t->patterns = xcalloc(t->npatterns, sizeof(*t->patterns));
		LY_ARRAY_FOR(str->patterns, u) {
			t->patterns[u].expr = xstrdup(str->patterns[u]->expr);
			t->patterns[u].invert = str->patterns[u]->inverted;
			t->patterns[u].emsg =
			    xstrdup_or_null(str->patterns[u]->emsg);
			t->patterns[u].eapptag =
			    xstrdup_or_null(str->patterns[u]->eapptag);
		}
		break;
	case ST_BINARY:
		t->length = conv_range(bin->length, false);
		break;
	case ST_ENUMERATION:
		items = en->enums;
		break;
	case ST_BITS:
		items = bits->bits;
		break;
	case ST_IDENTITYREF:
		t->nbases = LY_ARRAY_COUNT(idr->bases);
		t->bases = xcalloc(t->nbases, sizeof(*t->bases));
		LY_ARRAY_FOR(idr->bases, u)
			if ((t->bases[u] = schema_ident(c->s,
			    idr->bases[u]->module->name,
			    idr->bases[u]->name)) == NULL)
				errx(2, "libyang: identity %s:%s not found",
				    idr->bases[u]->module->name,
				    idr->bases[u]->name);
		break;
	case ST_LEAFREF:
		t->path = xstrdup(lyxp_get_expr(lr->path));
		t->cpath = xp_canon(t->path, lr->prefixes, c->cur);
		t->require_instance = lr->require_instance;
		t->real = conv_type(c, lr->realtype);
		break;
	case ST_INSTANCEID:
		t->require_instance = ii->require_instance;
		break;
	case ST_UNION:
		t->nmembers = LY_ARRAY_COUNT(un->types);
		t->members = xcalloc(t->nmembers, sizeof(*t->members));
		LY_ARRAY_FOR(un->types, u)
			t->members[u] = conv_type(c, un->types[u]);
		break;
	default:
		break;
	}
	if (items != NULL) {
		/* An enum or a bit a disabled feature guards is left out. */
		t->items = xcalloc(LY_ARRAY_COUNT(items), sizeof(*t->items));
		LY_ARRAY_FOR(items, u) {
			struct sitem *it;

			if ((items[u].flags & LYS_DISABLED) != 0)
				continue;
			it = &t->items[t->nitems++];
			it->name = xstrdup(items[u].name);
			it->value = t->base == ST_BITS ?
			    (int64_t)items[u].position : items[u].value;
			if ((items[u].flags & LYS_STATUS_DEPRC) != 0)
				it->flags |= SNF_DEPRECATED;
			if ((items[u].flags & LYS_STATUS_OBSLT) != 0)
				it->flags |= SNF_OBSOLETE;
		}
	}
	return (t);
}

/*
 * An sx:augment-structure's nodes as written: libyang's structure plugin
 * keeps them in an augment of its own, a substatement of the parsed
 * instance, which is found as the plugin finds it, by its argument.
 */
static struct swnode *
conv_augstruct(const struct lysc_ext_instance *ce)
{
	const struct lysp_ext_instance *pe;
	LY_ARRAY_COUNT_TYPE u, v;

	if (ce->module == NULL || ce->module->parsed == NULL ||
	    ce->argument == NULL)
		return (NULL);
	LY_ARRAY_FOR(ce->module->parsed->exts, u) {
		pe = &ce->module->parsed->exts[u];
		if (pe->def == NULL || pe->def->compiled != ce->def ||
		    pe->argument == NULL || strcmp(pe->argument,
		    ce->argument) != 0)
			continue;
		LY_ARRAY_FOR(pe->substmts, v)
			if (pe->substmts[v].stmt == LY_STMT_AUGMENT &&
			    *pe->substmts[v].storage_p != NULL)
				return (conv_wchildren(
				    *pe->substmts[v].storage_p, NULL));
	}
	return (NULL);
}

/*
 * Extension instances, and the data nodes an instance holds (found with
 * lyplg_ext_get_storage(), as libyang's structure and yang-data plugins
 * keep them).  An instance without a module is a copy libyang made from
 * an ancestor.
 */
static struct sext *
conv_exts(struct conv *c, struct lysc_ext_instance *le, size_t *np)
{
	const struct lysc_node *first;
	struct sext *e;
	LY_ARRAY_COUNT_TYPE u;

	*np = LY_ARRAY_COUNT(le);
	if (*np == 0)
		return (NULL);
	e = xcalloc(*np, sizeof(*e));
	LY_ARRAY_FOR(le, u) {
		e[u].ext = xasprintf("%s:%s", le[u].def->module->name,
		    le[u].def->name);
		e[u].arg = xstrdup_or_null(le[u].argument);
		e[u].inherited = le[u].module == NULL;
		e[u].module = le[u].module != NULL ?
		    smod_of(c, le[u].module) : NULL;
		first = NULL;
		if (lyplg_ext_get_storage(&le[u], LY_STMT_DATA_NODE_MASK,
		    sizeof(first), (const void **)&first) == LY_SUCCESS &&
		    first != NULL) {
			struct sext *saved = c->in;

			c->in = &e[u];
			e[u].data = conv_list(c, first, NULL);
			c->in = saved;
		}
		if (strcmp(e[u].ext,
		    "ietf-yang-structure-ext:augment-structure") == 0)
			e[u].written = conv_augstruct(&le[u]);
	}
	return (e);
}

static void
add_dflt(struct conv *c, struct snode *n, const struct lyd_value *v)
{

	n->dflts = xreallocarray(n->dflts, n->ndflts + 1, sizeof(*n->dflts));
	n->dflts[n->ndflts++] = xstrdup(lyd_value_get_canonical(c->ctx, v));
}

static struct snode *snode_below(struct snode *, const struct lysc_node *,
    const struct lysc_node *);

static struct snode *
conv_node(struct conv *c, const struct lysc_node *ln, struct snode *parent)
{
	struct snode *n, **tail;
	const struct lysc_node_action *a;
	const struct lysc_node_notif *no;
	const struct lysp_node *pn;

	n = xcalloc(1, sizeof(*n));
	n->kind = kind_of(ln->nodetype);
	n->name = xstrdup(ln->name);
	n->module = smod_of(c, ln->module);
	n->parent = parent;
	n->in = c->in;
	n->lyn = ln;
	c->cur = n->module->name;
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
		LY_ARRAY_COUNT_TYPE u;

		n->min = l->min;
		n->max = l->max;
		n->type = conv_type(c, l->type);
		n->units = xstrdup_or_null(l->units);
		LY_ARRAY_FOR(l->dflts, u)
			add_dflt(c, n, l->dflts[u]);
	} else if (ln->nodetype == LYS_LEAF) {
		const struct lysc_node_leaf *l = (const void *)ln;

		n->type = conv_type(c, l->type);
		n->units = xstrdup_or_null(l->units);
		if (l->dflt != NULL)
			add_dflt(c, n, l->dflt);
	}
	{
		struct lysc_when **when = lysc_node_when(ln);
		struct lysc_must *must = lysc_node_musts(ln);
		LY_ARRAY_COUNT_TYPE u;

		n->nwhen = LY_ARRAY_COUNT(when);
		n->when = xcalloc(n->nwhen, sizeof(*n->when));
		n->cwhen = xcalloc(n->nwhen, sizeof(*n->cwhen));
		n->whenctx = xcalloc(n->nwhen + 1, sizeof(*n->whenctx));
		LY_ARRAY_FOR(when, u) {
			n->when[u] = xstrdup(lyxp_get_expr(when[u]->cond));
			n->cwhen[u] = xp_canon(n->when[u], when[u]->prefixes,
			    n->module->name);
			n->whenctx[u] = when[u]->context == ln ? SWC_SELF :
			    when[u]->context == NULL ? SWC_ROOT : SWC_PARENT;
		}
		n->nmusts = LY_ARRAY_COUNT(must);
		n->musts = xcalloc(n->nmusts, sizeof(*n->musts));
		LY_ARRAY_FOR(must, u) {
			n->musts[u].expr = xstrdup(lyxp_get_expr(must[u].cond));
			n->musts[u].cexpr = xp_canon(n->musts[u].expr,
			    must[u].prefixes, n->module->name);
			n->musts[u].emsg = xstrdup_or_null(must[u].emsg);
			n->musts[u].eapptag = xstrdup_or_null(must[u].eapptag);
		}
	}

	/*
	 * What only the parsed node says: its if-features and its type as
	 * written.  An implicit case has none: libyang made its parsed node
	 * only to compile it.
	 */
	if ((pn = ln->priv) != NULL) {
		if ((pn->flags & LYS_INTERNAL) != 0)
			n->flags |= SNF_INTERNAL;
		n->iffeatures = conv_iffeatures(pn->iffeatures,
		    &n->niffeatures);
		conv_wtype(pn, &n->wtype, &n->wpath);
	}

	n->exts = conv_exts(c, ln->exts, &n->nexts);

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

	if (n->kind == SN_CHOICE &&
	    ((const struct lysc_node_choice *)(const void *)ln)->dflt != NULL) {
		const char *dn = ((const struct lysc_node_choice *)(const void *)
		    ln)->dflt->name;

		for (struct snode *ch = n->child; ch != NULL; ch = ch->next)
			if (strcmp(ch->name, dn) == 0)
				n->dflt_case = ch;
	}
	if (n->kind == SN_LIST) {
		const struct lysc_node_list *l = (const void *)ln;
		LY_ARRAY_COUNT_TYPE u, v;

		for (struct snode *ch = n->child; ch != NULL; ch = ch->next)
			if ((ch->flags & SNF_KEY) != 0) {
				n->keys = xreallocarray(n->keys, n->nkeys + 1,
				    sizeof(*n->keys));
				n->keys[n->nkeys++] = ch;
			}
		n->nuniques = LY_ARRAY_COUNT(l->uniques);
		n->uniques = xcalloc(n->nuniques + 1, sizeof(*n->uniques));
		LY_ARRAY_FOR(l->uniques, u) {
			struct sunique *un = &n->uniques[u];

			un->n = LY_ARRAY_COUNT(l->uniques[u]);
			un->leaf = xcalloc(un->n + 1, sizeof(*un->leaf));
			LY_ARRAY_FOR(l->uniques[u], v)
				un->leaf[v] = snode_below(n, ln,
				    &l->uniques[u][v]->node);
		}
	}
	return (n);
}

/*
 * The node of n's tree that is ln's descendant d: down from n by the names
 * (and modules) of d's ancestors below ln, choices and cases included.
 */
static struct snode *
snode_below(struct snode *n, const struct lysc_node *ln,
    const struct lysc_node *d)
{
	const struct lysc_node *chain[64];
	size_t depth = 0;
	struct snode *at = n, *ch;

	for (const struct lysc_node *x = d; x != NULL && x != ln;
	    x = x->parent) {
		if (depth == sizeof(chain) / sizeof(chain[0]))
			return (NULL);
		chain[depth++] = x;
	}
	while (depth > 0) {
		const struct lysc_node *x = chain[--depth];

		for (ch = at->child; ch != NULL; ch = ch->next)
			if (strcmp(ch->name, x->name) == 0 &&
			    strcmp(ch->module->name, x->module->name) == 0)
				break;
		if ((at = ch) == NULL)
			return (NULL);
	}
	return (at);
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

/*
 * The module's augments of other modules' trees, as written: those of its
 * own tree are in the compiled tree as any other node.  Those of its
 * submodules are left out, as yanglint leaves them out of the module's
 * tree diagram.
 */
static void
conv_augments(struct smodule *m, const struct lys_module *lm)
{
	const struct lysp_node_augment *aug;
	const char *id, *colon, *slash;
	struct saugment *sa;

	if (lm->parsed == NULL)
		return;
	for (aug = lm->parsed->augments; aug != NULL; aug = aug->next) {
		id = aug->nodeid + (aug->nodeid[0] == '/');
		colon = strchr(id, ':');
		slash = strchr(id, '/');
		if (colon == NULL || (slash != NULL && slash < colon) ||
		    (strncmp(id, lm->prefix, (size_t)(colon - id)) == 0 &&
		    lm->prefix[colon - id] == '\0'))
			continue;	/* its own tree */
		m->augments = xreallocarray(m->augments, m->naugments + 1,
		    sizeof(*m->augments));
		sa = &m->augments[m->naugments++];
		sa->target = xstrdup(aug->nodeid);
		sa->nodes = conv_wchildren(&aug->node, NULL);
	}
}

/* Each node of the trees, structures' too, in turn. */
static void
walk_trees(struct snode *n, void (*visit)(struct snode *, void *),
    void *arg)
{

	for (; n != NULL; n = n->next) {
		visit(n, arg);
		walk_trees(n->child, visit, arg);
	}
}

static void
walk_schema(struct schema *s, void (*visit)(struct snode *, void *),
    void *arg)
{

	for (size_t i = 0; i < s->nmods; i++) {
		walk_trees(s->mods[i]->data, visit, arg);
		walk_trees(s->mods[i]->rpcs, visit, arg);
		walk_trees(s->mods[i]->notifs, visit, arg);
		for (size_t j = 0; j < s->mods[i]->nexts; j++)
			walk_trees(s->mods[i]->exts[j].data, visit, arg);
	}
}

struct lref {
	struct schema	*s;
	const void	*want;
	struct snode	*found;
};

static void
find_lyn(struct snode *n, void *arg)
{
	struct lref *l = arg;

	if (l->found == NULL && n->lyn == l->want)
		l->found = n;
}

/* A leafref leaf's target, as libyang resolved its path. */
static void
resolve_lref(struct snode *n, void *arg)
{
	struct lref l = { .s = arg };

	if ((n->kind != SN_LEAF && n->kind != SN_LEAFLIST) || n->type == NULL ||
	    n->type->base != ST_LEAFREF || n->lyn == NULL)
		return;
	if ((l.want = lysc_node_lref_target(n->lyn)) == NULL)
		return;
	walk_schema(l.s, find_lyn, &l);
	n->lref = l.found;
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
	c.ctx = ctx;
	/* Every module, implemented or only imported: identities. */
	while ((lm = ly_ctx_get_module_iter(ctx, &idx)) != NULL) {
		m = xcalloc(1, sizeof(*m));
		m->name = xstrdup(lm->name);
		m->revision = lm->revision != NULL ? xstrdup(lm->revision) :
		    NULL;
		m->ns = xstrdup(lm->ns);
		m->prefix = xstrdup(lm->prefix);
		m->implemented = lm->implemented && lm->compiled != NULL;
		for (size_t j = 0; j < nsrcs && !m->given; j++)
			m->given = srcs[j].given &&
			    strcmp(srcs[j].name, lm->name) == 0 &&
			    (srcs[j].rev == NULL || (lm->revision != NULL &&
			    strcmp(srcs[j].rev, lm->revision) == 0));
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
			memset(&m->features[m->nfeatures], 0,
			    sizeof(*m->features));
			m->features[m->nfeatures].name = xstrdup(f->name);
			m->features[m->nfeatures++].enabled =
			    (f->flags & LYS_FENABLED) != 0;
		}
		/* An identity a disabled feature guards is left out. */
		m->idents = xcalloc(LY_ARRAY_COUNT(lm->identities),
		    sizeof(*m->idents));
		LY_ARRAY_FOR(lm->identities, u) {
			struct sident *ni;

			if (lys_identity_iffeature_value(&lm->identities[u]) !=
			    LY_SUCCESS)
				continue;
			ni = &m->idents[m->nidents++];
			ni->module = m;
			ni->name = xstrdup(lm->identities[u].name);
			if ((lm->identities[u].flags & LYS_STATUS_DEPRC) != 0)
				ni->flags |= SNF_DEPRECATED;
			if ((lm->identities[u].flags & LYS_STATUS_OBSLT) != 0)
				ni->flags |= SNF_OBSOLETE;
		}
		LY_ARRAY_FOR(lm->deviated_by, u) {
			m->deviated_by = xreallocarray(m->deviated_by,
			    m->ndeviated_by + 1, sizeof(*m->deviated_by));
			m->deviated_by[m->ndeviated_by++] =
			    xstrdup(lm->deviated_by[u]->name);
		}
		/* What it imports, at the revision bound. */
		if (lm->parsed != NULL)
			LY_ARRAY_FOR(lm->parsed->imports, u) {
				const struct lysp_import *im =
				    &lm->parsed->imports[u];

				m->imports = xreallocarray(m->imports,
				    m->nimports + 1, sizeof(*m->imports));
				m->imports[m->nimports].name = xstrdup(im->name);
				m->imports[m->nimports++].revision =
				    im->module != NULL &&
				    im->module->revision != NULL ?
				    xstrdup(im->module->revision) : NULL;
			}
	}
	/* Derived identities, now that every module has its own. */
	for (i = 0; i < c.s->nmods; i++) {
		lm = c.lmods[i];
		LY_ARRAY_FOR(lm->identities, u) {
			si = schema_ident_in(c.s->mods[i],
			    lm->identities[u].name);
			if (si == NULL)
				continue;	/* disabled */
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
		c.s->mods[i]->exts = conv_exts(&c, lm->compiled->exts,
		    &c.s->mods[i]->nexts);
		conv_augments(c.s->mods[i], lm);
	}
	walk_schema(c.s, resolve_lref, c.s);
	free(c.lmods);
	return (c.s);
}
