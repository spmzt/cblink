/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * NACM's paths (RFC 8341 section 3.4.5, PLAN-SDN-YANG 2.2.5): a
 * data-node rule's node-instance-identifier, an instance-identifier whose
 * key predicates may be left out (any entry, then) and whose values may
 * be $USER, the session's user.  "/" is every node.  A path matches the
 * node it names and all below it.  Names are by module, as the tables
 * have them (an unprefixed one its step's, or its previous step's).
 * The path is compiled once, against the schema: each step to its node,
 * each value to its key's type; matching is a walk up from the node.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_data.h"
#include "cbl_dimpl.h"
#include "cbl_xpath.h"
#include "cbl_yimpl.h"

struct npred {
	const struct cbl_ynode	*key;	/* a key leaf; the leaf-list: [.=v] */
	bool			 user;	/* $USER */
	void			*value;	/* else the value, in the arena */
};

struct nstep {
	const struct cbl_ynode	*sn;
	struct npred		*preds;
	size_t			 npreds;
};

struct cbl_dnacm_path {
	const struct cbl_yschema *schema;
	struct nstep		*steps;		/* none: "/", every node */
	size_t			 nsteps;
	cbl_yarena		*a;
};

static int
fail(char *why, size_t whylen, const char *fmt, ...)
{
	va_list ap;

	if (why != NULL && whylen > 0) {
		va_start(ap, fmt);
		vsnprintf(why, whylen, fmt, ap);
		va_end(ap);
	}
	return (EINVAL);
}

/* A schema node named mod:name among nodes k. */
static const struct cbl_ynode *
named(const struct cbl_ynode *const *k, uint32_t nk, const char *mod,
    const char *name)
{

	for (uint32_t i = 0; i < nk; i++)
		if (strcmp(k[i]->name, name) == 0 &&
		    strcmp(k[i]->module->name, mod) == 0)
			return (k[i]);
	return (NULL);
}

/* A predicate's value, s, parsed as node n's type into the arena. */
static int
value(struct cbl_dnacm_path *p, const struct cbl_ynode *n, const char *s,
    void **out, char *why, size_t whylen)
{
	size_t len = strlen(s) + 1;
	char *copy;
	void *v;
	int error;

	/* A string's value is the string parsed: the path's own copy. */
	if ((v = cbl_yarena_alloc(p->a, n->type->csize > 0 ? n->type->csize :
	    1)) == NULL || (copy = cbl_yarena_alloc(p->a, len)) == NULL)
		return (ENOMEM);
	memcpy(copy, s, len);
	if ((error = cbl_yvalue_parse(n, n->type, copy, v, p->a)) != 0)
		return (fail(why, whylen, "%s: '%s' not a value of it",
		    n->name, s));
	*out = v;
	return (0);
}

static int
pred(struct cbl_dnacm_path *p, const struct cbl_ynode *sn, const char *mod,
    const struct cbl_xp *x, struct npred *pr, char *why, size_t whylen)
{
	const struct cbl_xp *l, *r;
	char num[64];

	if (x->kind != CBL_XP_EQ)
		return (fail(why, whylen, "%s: a predicate not key = value",
		    sn->name));
	l = x->args[0];
	r = x->args[1];
	/* A relative path of one step: the step. */
	if (l->kind == CBL_XP_PATH && !l->absolute && l->base == NULL &&
	    l->nargs == 1)
		l = l->args[0];
	if (l->kind != CBL_XP_STEP || l->npreds > 0)
		return (fail(why, whylen, "%s: a predicate not key = value",
		    sn->name));
	if (l->axis == CBL_XA_SELF && l->test == CBL_XT_NODE &&
	    sn->kind == CBL_YN_LEAFLIST)
		pr->key = sn;
	else if (l->axis == CBL_XA_CHILD && l->test == CBL_XT_NAME &&
	    sn->kind == CBL_YN_LIST) {
		pr->key = named(sn->child, sn->nchild, l->prefix != NULL ?
		    l->prefix : mod, l->s);
		if (pr->key == NULL || (pr->key->flags & CBL_YNF_KEY) == 0)
			return (fail(why, whylen, "%s: %s not a key of it",
			    sn->name, l->s));
	} else
		return (fail(why, whylen, "%s: a predicate not key = value",
		    sn->name));
	switch (r->kind) {
	case CBL_XP_VAR:
		if (r->prefix != NULL || strcmp(r->s, "USER") != 0)
			return (fail(why, whylen, "$%s: not a variable NACM "
			    "has", r->s));
		pr->user = true;
		return (0);
	case CBL_XP_LITERAL:
		return (value(p, pr->key, r->s, &pr->value, why, whylen));
	case CBL_XP_NUMBER:
		snprintf(num, sizeof(num), "%.17g", r->num);
		return (value(p, pr->key, num, &pr->value, why, whylen));
	default:
		return (fail(why, whylen, "%s: a predicate not key = value",
		    sn->name));
	}
}

cbl_dnacm_path *
cbl_dnacm_path_new(const struct cbl_yschema *s, const char *path, char *why,
    size_t whylen)
{
	const struct cbl_ynode *const *k = NULL;
	const struct cbl_ymodule *m;
	struct cbl_dnacm_path *p;
	struct cbl_xp *x = NULL;
	const char *mod = NULL;
	char perr[128];
	size_t pos;
	uint32_t nk = 0;
	int error = 0;

	if (why != NULL && whylen > 0)
		why[0] = '\0';
	if (s == NULL || path == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	if ((p = calloc(1, sizeof(*p))) == NULL ||
	    (p->a = cbl_yarena_new()) == NULL) {
		free(p);
		return (NULL);
	}
	p->schema = s;
	if ((x = cbl_xp_parse(path, perr, sizeof(perr), &pos)) == NULL) {
		error = fail(why, whylen, "at %zu: %s", pos, perr);
		goto out;
	}
	if (x->kind != CBL_XP_PATH || !x->absolute || x->base != NULL) {
		error = fail(why, whylen, "not an absolute path");
		goto out;
	}
	if (x->nargs > 0 && (p->steps = calloc(x->nargs,
	    sizeof(*p->steps))) == NULL) {
		error = ENOMEM;
		goto out;
	}
	for (size_t i = 0; i < x->nargs && error == 0; i++) {
		const struct cbl_xp *st = x->args[i];
		struct nstep *ns = &p->steps[i];

		if (st->kind != CBL_XP_STEP || st->axis != CBL_XA_CHILD ||
		    st->test != CBL_XT_NAME) {
			error = fail(why, whylen, "step %zu: not a node's name",
			    i + 1);
			break;
		}
		if (st->prefix != NULL)
			mod = st->prefix;
		else if (mod == NULL) {
			error = fail(why, whylen, "%s: no module", st->s);
			break;
		}
		if (i == 0) {
			for (uint32_t j = 0; j < s->nmod; j++)
				if (strcmp(s->mod[j]->name, mod) == 0) {
					m = s->mod[j];
					k = m->top;
					nk = m->ntop;
				}
		}
		if ((ns->sn = named(k, nk, mod, st->s)) == NULL) {
			error = fail(why, whylen, "%s:%s: no such node", mod,
			    st->s);
			break;
		}
		k = ns->sn->child;
		nk = ns->sn->nchild;
		p->nsteps++;
		if (st->npreds == 0)
			continue;
		if ((ns->preds = cbl_yarena_alloc(p->a, st->npreds *
		    sizeof(*ns->preds))) == NULL) {
			error = ENOMEM;
			break;
		}
		memset(ns->preds, 0, st->npreds * sizeof(*ns->preds));
		for (size_t j = 0; j < st->npreds && error == 0; j++) {
			error = pred(p, ns->sn, mod, st->preds[j],
			    &ns->preds[j], why, whylen);
			ns->npreds++;
		}
	}
out:
	cbl_xp_free(x);
	if (error != 0) {
		cbl_dnacm_path_free(p);
		errno = error;
		return (NULL);
	}
	return (p);
}

void
cbl_dnacm_path_free(cbl_dnacm_path *p)
{

	if (p == NULL)
		return;
	free(p->steps);
	cbl_yarena_free(p->a);
	free(p);
}

/* Whether entry or leaf-list value n passes predicate pr, for user. */
static bool
passes(const struct npred *pr, const cbl_dnode *n, const char *user)
{
	const cbl_dnode *k = pr->key == n->sn ? n : cbl_dnode_child(n,
	    pr->key);
	const void *want = pr->value;
	cbl_yarena *a = NULL;
	void *v;
	bool ok;

	if (k == NULL || k->value == NULL)
		return (false);
	if (pr->user) {
		if (user == NULL || (a = cbl_yarena_new()) == NULL ||
		    (v = cbl_yarena_alloc(a, pr->key->type->csize > 0 ?
		    pr->key->type->csize : 1)) == NULL ||
		    cbl_yvalue_parse(pr->key, pr->key->type, user, v, a) !=
		    0) {
			cbl_yarena_free(a);
			return (false);
		}
		want = v;
	}
	ok = cbl_dvalue_equal(pr->key->type, k->value, want);
	cbl_yarena_free(a);
	return (ok);
}

bool
cbl_dnacm_path_match(const cbl_dnacm_path *p, const cbl_dnode *n,
    const char *user)
{
	const cbl_dnode *chain[CBL_D_DEPTH_MAX + 1];
	size_t nc = 0;

	if (p == NULL || n == NULL)
		return (false);
	if (p->nsteps == 0)
		return (true);
	for (const cbl_dnode *a = n; a != NULL && a->sn != NULL;
	    a = a->parent) {
		if (nc == CBL_D_DEPTH_MAX + 1)
			return (false);
		chain[nc++] = a;
	}
	if (nc < p->nsteps)
		return (false);
	/* chain[nc - 1] is the top: step i, chain[nc - 1 - i]. */
	for (size_t i = 0; i < p->nsteps; i++) {
		const cbl_dnode *x = chain[nc - 1 - i];
		const struct nstep *st = &p->steps[i];

		if (x->sn != st->sn)
			return (false);
		for (size_t j = 0; j < st->npreds; j++)
			if (!passes(&st->preds[j], x, user))
				return (false);
	}
	return (true);
}

bool
cbl_dnacm_path_match_schema(const cbl_dnacm_path *p,
    const struct cbl_ynode *sn)
{
	const struct cbl_ynode *chain[CBL_D_DEPTH_MAX + 1];
	size_t nc = 0;

	if (p == NULL || sn == NULL)
		return (false);
	if (p->nsteps == 0)
		return (true);
	for (const struct cbl_ynode *a = sn; a != NULL; a = a->parent) {
		if (nc == CBL_D_DEPTH_MAX + 1)
			return (false);
		chain[nc++] = a;
	}
	if (nc < p->nsteps)
		return (false);
	for (size_t i = 0; i < p->nsteps; i++)
		if (chain[nc - 1 - i] != p->steps[i].sn ||
		    p->steps[i].npreds > 0)
			return (false);
	return (true);
}
