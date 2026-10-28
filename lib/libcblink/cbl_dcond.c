/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * when and must over an instance tree (cbl_data.h, PLAN-SDN-YANG 2.2.4),
 * by the evaluator (cbl_xpeval.c).
 *
 * A node's whens are its choices' and their cases', outermost last, and
 * its own (an augment's or a uses' among them, the tables having them on
 * each node they bring).  Each is evaluated as RFC 7950 section 7.21.5
 * has it: an augment's, a uses', a choice's and a case's from the
 * closest ancestor that is a data node, the nodes it brings not there; a
 * node's own from the node, made a dummy with no value and no children.
 * A must is evaluated from its node (section 7.5.3).  The tree should
 * have its defaults made (cbl_dtree_defaults()): XPath in YANG sees them
 * (section 6.4.1).
 */

#include <sys/types.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "cbl_data.h"
#include "cbl_dimpl.h"

/* Whether schema node sn is in choice ch (case k, -1: any). */
static bool
in_choice(const struct cbl_ynode *sn, const struct cbl_ychoice *ch, int k)
{
	uint16_t kk = sn->ccase;

	for (const struct cbl_ychoice *x = sn->choice; x != NULL;
	    kk = x->parent_case, x = x->parent)
		if (x == ch)
			return (k < 0 || kk == k);
	return (false);
}

struct hide_choice {
	const struct cbl_ychoice *ch;
	int			 k;
};

static bool
hide_choice(const void *arg, const struct cbl_ynode *sn)
{
	const struct hide_choice *h = arg;

	return (in_choice(sn, h->ch, h->k));
}

/* The nodes an augment's or a uses' when brings: each has it too. */
static bool
hide_when(const void *arg, const struct cbl_ynode *sn)
{
	const struct cbl_ywhen *w = arg;

	for (uint16_t i = 0; i < sn->nwhen; i++)
		if (sn->when[i].expr == w->expr && sn->when[i].ctx == w->ctx)
			return (true);
	return (false);
}

static int
eval_bool(const cbl_dtree *t, int32_t expr, const cbl_dnode *ctx,
    const struct cbl_d_view *view, bool *out, char *why, size_t whylen)
{
	struct cbl_xval v;
	int error;

	if (expr < 0 || (uint32_t)expr >= t->schema->nxpath) {
		snprintf(why, whylen, "no expression %d", (int)expr);
		return (EINVAL);
	}
	if ((error = cbl_d_xp_eval(t, t->schema->xpath[expr], ctx, ctx, view,
	    &v, why, whylen)) != 0)
		return (error);
	*out = v.kind == CBL_XV_NODES ? v.n > 0 : v.kind == CBL_XV_BOOL ?
	    v.b : v.kind == CBL_XV_NUMBER ? v.num != 0 && v.num == v.num :
	    v.s != NULL && v.s[0] != '\0';
	cbl_xval_free(&v);
	return (0);
}

/*
 * Whether node c's whens all hold: 0 and *ok; or an errno, the evaluator
 * failing, and why.  *expr, one that does not hold.
 */
static int
whens(const cbl_dtree *t, const cbl_dnode *c, bool *ok, int32_t *expr,
    char *why, size_t whylen)
{
	const cbl_dnode *p = c->parent, *root = &t->root;
	const struct cbl_ywhen *w;
	struct hide_choice hc;
	struct cbl_d_view view;
	uint16_t k = c->sn->ccase;
	int error;

	*ok = true;
	for (const struct cbl_ychoice *ch = c->sn->choice; ch != NULL;
	    k = ch->parent_case, ch = ch->parent) {
		for (int pass = 0; pass < 2; pass++) {
			uint16_t n = pass == 0 ? ch->nwhen : ch->cases[k].nwhen;

			w = pass == 0 ? ch->when : ch->cases[k].when;
			hc = (struct hide_choice){ ch, pass == 0 ? -1 : k };
			view = (struct cbl_d_view){ .hpar = p,
			    .hide = hide_choice, .harg = &hc };
			for (uint16_t i = 0; i < n; i++) {
				if ((error = eval_bool(t, w[i].expr,
				    w[i].ctx == CBL_YWC_ROOT ? root : p, &view,
				    ok, why, whylen)) != 0)
					return (error);
				if (!*ok) {
					*expr = w[i].expr;
					return (0);
				}
			}
		}
	}
	for (uint16_t i = 0; i < c->sn->nwhen; i++) {
		w = &c->sn->when[i];
		if (w->ctx == CBL_YWC_SELF)
			view = (struct cbl_d_view){ .dummy = c };
		else
			view = (struct cbl_d_view){ .hpar = p,
			    .hide = hide_when, .harg = w };
		if ((error = eval_bool(t, w->expr, w->ctx == CBL_YWC_SELF ? c :
		    w->ctx == CBL_YWC_ROOT ? root : p, &view, ok, why,
		    whylen)) != 0)
			return (error);
		if (!*ok) {
			*expr = w->expr;
			return (0);
		}
	}
	return (0);
}

struct cond {
	const cbl_dtree		*t;
	struct cbl_dederr	*err;
};

static int
fail(struct cond *r, int error, const cbl_dnode *at, const char *tag,
    const char *apptag, const char *fmt, ...)
{
	va_list ap;

	if (r->err != NULL) {
		r->err->node = at;
		r->err->tag = tag;
		r->err->apptag = apptag;
		va_start(ap, fmt);
		vsnprintf(r->err->msg, sizeof(r->err->msg), fmt, ap);
		va_end(ap);
	}
	return (error);
}

/*
 * A mandatory leaf, a list or leaf-list of min-elements, of n's schema
 * that brings a when (an augment's, a uses'), missing where the when
 * holds: what the struct validator cannot judge (cbl_yvalid.c leaves
 * them here).  A node's own when, or one in a case, is not judged.
 */
static int
mandatory_whens(struct cond *r, const cbl_dnode *n, int depth)
{
	const struct cbl_ynode *sn = n->sn;
	struct cbl_d_view view;
	char why[128];
	bool ok;
	int error;

	if (depth > CBL_D_DEPTH_MAX)
		return (ELOOP);
	for (uint32_t i = 0; sn != NULL && i < sn->nchild; i++) {
		const struct cbl_ynode *c = sn->child[i];
		const cbl_dnode *x;
		bool need, own = false;

		if (c->nwhen == 0 || c->choice != NULL ||
		    (c->flags & CBL_YNF_CONFIG) == 0)
			continue;
		need = (c->kind == CBL_YN_LEAF && (c->flags &
		    CBL_YNF_MANDATORY) != 0) || ((c->kind == CBL_YN_LIST ||
		    c->kind == CBL_YN_LEAFLIST) && c->min > 0);
		if (!need)
			continue;
		for (x = n->first; x != NULL; x = x->next)
			if (x->sn == c)
				break;
		if (x != NULL)
			continue;
		ok = true;
		for (uint16_t k = 0; ok && k < c->nwhen; k++) {
			const struct cbl_ywhen *w = &c->when[k];

			if (w->ctx == CBL_YWC_SELF) {
				own = true;
				break;
			}
			view = (struct cbl_d_view){ .hpar = n,
			    .hide = hide_when, .harg = w };
			if ((error = eval_bool(r->t, w->expr, w->ctx ==
			    CBL_YWC_ROOT ? &r->t->root : n, &view, &ok, why,
			    sizeof(why))) != 0)
				return (fail(r, error, n, "operation-failed",
				    NULL, "%s: %s", c->name, why));
		}
		if (ok && !own)
			return (fail(r, EINVAL, n, "missing-element", NULL,
			    "%s: mandatory, missing", c->name));
	}
	return (0);
}

static int	check(struct cond *, const cbl_dnode *, int);

/* Node c: its whens and musts, what must be under it, and below. */
static int
check_node(struct cond *r, const cbl_dnode *c, int depth)
{
	const struct cbl_yschema *s = r->t->schema;
	char why[128];
	int32_t expr;
	bool ok;
	int error;

	if ((error = whens(r->t, c, &ok, &expr, why, sizeof(why))) != 0)
		return (fail(r, error, c, "operation-failed", NULL, "%s: %s",
		    c->sn->name, why));
	/* A default under a false when: not in use, no error. */
	if (!ok && (c->flags & CBL_DN_DEFAULT) != 0)
		return (0);
	if (!ok)
		return (fail(r, EINVAL, c, "unknown-element", NULL,
		    "%s: when %s: false", c->sn->name, s->xpath[expr]));
	for (uint16_t i = 0; i < c->sn->nmust; i++) {
		const struct cbl_ymust *m = &c->sn->must[i];

		if ((error = eval_bool(r->t, m->expr, c, NULL, &ok, why,
		    sizeof(why))) != 0)
			return (fail(r, error, c, "operation-failed", NULL,
			    "%s: %s", c->sn->name, why));
		if (ok)
			continue;
		if (m->emsg != NULL)
			return (fail(r, EINVAL, c, "operation-failed",
			    m->eapptag != NULL ? m->eapptag : "must-violation",
			    "%s", m->emsg));
		return (fail(r, EINVAL, c, "operation-failed", m->eapptag !=
		    NULL ? m->eapptag : "must-violation", "%s: must %s: false",
		    c->sn->name, s->xpath[m->expr]));
	}
	if ((error = mandatory_whens(r, c, depth)) != 0)
		return (error);
	return (c->first != NULL ? check(r, c, depth + 1) : 0);
}

static int
check(struct cond *r, const cbl_dnode *n, int depth)
{
	int error;

	if (depth > CBL_D_DEPTH_MAX)
		return (ELOOP);
	for (const cbl_dnode *c = n->first; c != NULL; c = c->next)
		if ((error = check_node(r, c, depth)) != 0)
			return (error);
	return (0);
}

int
cbl_dtree_check_conds(const cbl_dtree *t, struct cbl_dederr *err)
{
	struct cond r = { .t = t, .err = err };

	if (err != NULL)
		memset(err, 0, sizeof(*err));
	if (t == NULL)
		return (EINVAL);
	return (check(&r, &t->root, 0));
}

int
cbl_dnode_check_conds(const cbl_dtree *t, const cbl_dnode *n,
    struct cbl_dederr *err)
{
	struct cond r = { .t = t, .err = err };

	if (err != NULL)
		memset(err, 0, sizeof(*err));
	if (t == NULL || n == NULL)
		return (EINVAL);
	return (check_node(&r, n, 0));
}

/* The leaves and leaf-list entries of n's subtree, n's own if one. */
static ssize_t
leaves(const cbl_dnode *n, int depth)
{
	ssize_t k = n->sn->type != NULL ? 1 : 0;

	if (depth > CBL_D_DEPTH_MAX)
		return (0);
	for (const cbl_dnode *c = n->first; c != NULL; c = c->next)
		k += leaves(c, depth + 1);
	return (k);
}

/*
 * The defaults made under n whose whens do not hold, removed (they are
 * not in use), until none is: one removed may make another's false.  How
 * many leaves and leaf-list entries, or -1 and errno.
 */
static ssize_t
prune(cbl_dnode *n, int depth, int *error)
{
	char why[128];
	int32_t expr;
	ssize_t gone = 0, g;
	bool ok;

	if (depth > CBL_D_DEPTH_MAX) {
		*error = ELOOP;
		return (-1);
	}
	for (cbl_dnode *c = n->first, *next; c != NULL; c = next) {
		next = c->next;
		if ((c->flags & CBL_DN_DEFAULT) != 0) {
			if ((*error = whens(c->tree, c, &ok, &expr, why,
			    sizeof(why))) != 0)
				return (-1);
			if (!ok) {
				gone += leaves(c, 0);
				(void)cbl_dnode_remove(c);
				continue;
			}
		}
		if (c->first != NULL) {
			if ((g = prune(c, depth + 1, error)) < 0)
				return (-1);
			gone += g;
			/* A non-presence container made for defaults, now
			 * without one. */
			if (c->first == NULL && (c->flags & CBL_DN_DEFAULT) !=
			    0)
				(void)cbl_dnode_remove(c);
		}
	}
	return (gone);
}

ssize_t
cbl_d_prune_defaults(cbl_dnode *n)
{
	ssize_t gone = 0, g;
	int error = 0;

	do {
		if ((g = prune(n, 0, &error)) < 0) {
			errno = error;
			return (-1);
		}
		gone += g;
	} while (g > 0);
	return (gone);
}
