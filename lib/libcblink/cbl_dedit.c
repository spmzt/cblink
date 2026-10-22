/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Edits of an instance tree (cbl_data.h, PLAN-SDN-YANG 2.1.2): another
 * tree of the same schema, its nodes each with an operation or their
 * parent's (RFC 6241 section 7.2: merge, replace, create, delete,
 * remove; and none, the default that changes nothing not asked for),
 * applied to the target all or nothing.  Each change is written in an
 * undo log as it is made: a node added, a node taken away (kept, with
 * where it was, until the edit is done), a value replaced (the old one
 * kept); where one fails, the log is played back, last first, and the
 * target is as it was.  A node of a choice's case takes the place of
 * the other cases' (RFC 7950 section 7.9.2).  An ordered-by user list's
 * entry, or leaf-list's value, goes where its edit says (RFC 7950
 * section 7.8.6; YANG Patch's insert and move, RFC 8072), each move
 * logged with where it was.
 */

#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_data.h"
#include "cbl_dimpl.h"

enum ulkind { UL_ADDED, UL_REMOVED, UL_VALUE, UL_MOVED };

struct ul {
	enum ulkind	 kind;
	cbl_dnode	*n;
	cbl_dnode	*parent;	/* removed: where it was */
	cbl_dnode	*prev;		/* removed, moved: after what */
	void		*old;		/* value: the one replaced */
	uint16_t	 oflags;
};

struct edit {
	cbl_dtree		*t;
	struct ul		*log;
	size_t			 nlog, maxlog;
	struct cbl_dederr	*err;
};

static int
fail(struct edit *e, const cbl_dnode *at, const char *tag, int error,
    const char *fmt, ...)
{
	va_list ap;

	if (e->err != NULL) {
		e->err->node = at;
		e->err->tag = tag;
		va_start(ap, fmt);
		vsnprintf(e->err->msg, sizeof(e->err->msg), fmt, ap);
		va_end(ap);
	}
	return (error);
}

static int
logged(struct edit *e, const struct ul *u)
{
	struct ul *v;

	if (e->nlog == e->maxlog) {
		size_t n = e->maxlog > 0 ? e->maxlog * 2 : 32;

		if ((v = reallocarray(e->log, n, sizeof(*v))) == NULL)
			return (ENOMEM);
		e->log = v;
		e->maxlog = n;
	}
	e->log[e->nlog++] = *u;
	return (0);
}

/* A node taken out of the tree, kept to be put back or freed. */
static int
take(struct edit *e, cbl_dnode *n)
{
	struct ul u = { .kind = UL_REMOVED, .n = n, .parent = n->parent,
	    .prev = n->prev };
	int error;

	/* Logged first: if that fails, nothing has changed. */
	if ((error = logged(e, &u)) != 0)
		return (error);
	cbl_d_detach(n);
	return (0);
}

static int
added(struct edit *e, cbl_dnode *n)
{
	struct ul u = { .kind = UL_ADDED, .n = n };
	int error;

	if ((error = logged(e, &u)) != 0) {
		(void)cbl_dnode_remove(n);
		return (error);
	}
	return (0);
}

/* The nodes of parent in another case of a choice sn is in: taken. */
static int
other_cases(struct edit *e, cbl_dnode *parent, const struct cbl_ynode *sn)
{
	cbl_dnode *c, *next;
	int error;

	if (sn->choice == NULL)
		return (0);
	for (c = parent->first; c != NULL; c = next) {
		next = c->next;
		if (c->sn->choice != NULL && !cbl_d_same_case(sn, c->sn) &&
		    (error = take(e, c)) != 0)
			return (error);
	}
	return (0);
}

/* The keys of edit entry en, as cbl_dnode_add_entry() takes them. */
static int
keys_of(const cbl_dnode *en, const void **keys)
{

	for (uint16_t k = 0; k < en->sn->nkeys; k++)
		if ((keys[k] = cbl_d_key_value(en, k)) == NULL)
			return (EINVAL);
	return (0);
}

/* What in target parent tn edit node en is about, or NULL: none yet. */
static cbl_dnode *
match(const cbl_dnode *tn, const cbl_dnode *en)
{
	const void *keys[UINT8_MAX];

	switch (en->sn->kind) {
	case CBL_YN_LIST:
		if (en->sn->nkeys == 0 || en->sn->nkeys > nitems(keys) ||
		    keys_of(en, keys) != 0)
			return (NULL);
		return (cbl_dnode_entry(tn, en->sn, keys));
	case CBL_YN_LEAFLIST:
		return (cbl_dnode_llentry(tn, en->sn, en->value));
	default:
		return (cbl_dnode_child(tn, en->sn));
	}
}

/* The node of en made in tn: an entry with its keys, a value. */
static int
make(struct edit *e, cbl_dnode *tn, const cbl_dnode *en, cbl_dnode **out)
{
	const void *keys[UINT8_MAX];
	int error;

	if ((error = other_cases(e, tn, en->sn)) != 0)
		return (error);
	if (en->sn->kind == CBL_YN_LIST) {
		if (en->sn->nkeys > nitems(keys) ||
		    (en->sn->nkeys > 0 && keys_of(en, keys) != 0))
			return (fail(e, en, "missing-element", EINVAL,
			    "%s: its keys", en->sn->name));
		error = cbl_dnode_add_entry(tn, en->sn, keys, out);
	} else
		error = cbl_dnode_add(tn, en->sn, en->value, out);
	if (error != 0)
		return (fail(e, en, "operation-failed", error, "%s: %s",
		    en->sn->name, strerror(error)));
	return (added(e, *out));
}

/* The entry of tn that en's point names: by its keys, or its value. */
static cbl_dnode *
pointed(const cbl_dnode *tn, const cbl_dnode *en)
{

	if (en->sn->kind == CBL_YN_LIST)
		return (cbl_dnode_entry(tn, en->sn,
		    (const void *const *)en->point));
	return (cbl_dnode_llentry(tn, en->sn, en->point[0]));
}

/* x, made or there for edit node en, put where en says, the move logged. */
static int
place(struct edit *e, cbl_dnode *x, const cbl_dnode *en)
{
	struct ul u = { .kind = UL_MOVED, .n = x, .prev = x->prev };
	cbl_dnode *tn = x->parent, *pe, *after, *k;
	int error;

	if (en->where == 0)
		return (0);
	if ((en->sn->flags & CBL_YNF_USERORDER) == 0)
		return (fail(e, en, "bad-attribute", EINVAL,
		    "%s: ordered by the system, not where said",
		    en->sn->name));
	switch (en->where) {
	case CBL_DWHERE_FIRST:
		/* Before the first of its kind. */
		k = cbl_dnode_child(tn, x->sn);
		after = k == x ? x->prev : k->prev;
		break;
	case CBL_DWHERE_LAST:
		for (k = x; k->next != NULL && k->next->sn == x->sn;)
			k = k->next;
		after = k;
		break;
	default:
		if ((pe = pointed(tn, en)) == NULL) {
			error = fail(e, en, "bad-attribute", ENOENT,
			    "%s: missing-instance, no entry to go %s",
			    en->sn->name, en->where == CBL_DWHERE_BEFORE ?
			    "before" : "after");
			if (e->err != NULL)
				e->err->apptag = "missing-instance";
			return (error);
		}
		if (pe == x)
			return (fail(e, en, "bad-attribute", EINVAL,
			    "%s: before or after itself", en->sn->name));
		after = en->where == CBL_DWHERE_AFTER ? pe :
		    pe->prev == x ? x->prev : pe->prev;
		break;
	}
	if (after == x || x->prev == after)
		return (0);
	if ((error = logged(e, &u)) != 0)
		return (error);
	cbl_d_move_after(x, after);
	return (0);
}

static int	apply(struct edit *, cbl_dnode *, const cbl_dnode *, int, int);

/* en's children applied to tn's, each with op unless its own. */
static int
apply_children(struct edit *e, cbl_dnode *tn, const cbl_dnode *en, int op,
    int depth)
{
	int error;

	for (const cbl_dnode *c = en->first; c != NULL; c = c->next) {
		/* An entry's keys came with it, and are not edited. */
		if ((c->sn->flags & CBL_YNF_KEY) &&
		    en->sn->kind == CBL_YN_LIST)
			continue;
		if ((error = apply(e, tn, c, op, depth + 1)) != 0)
			return (error);
	}
	return (0);
}

/* A leaf's value replaced, the old one kept in the log. */
static int
revalue(struct edit *e, cbl_dnode *x, const void *value)
{
	struct ul u = { .kind = UL_VALUE, .n = x, .oflags = x->flags };
	int error;

	if (cbl_dvalue_equal(x->sn->type, x->value, value) &&
	    (x->flags & CBL_DN_DEFAULT) == 0)
		return (0);
	if ((error = logged(e, &u)) != 0)
		return (error);
	e->log[e->nlog - 1].old = x->value;
	x->value = NULL;
	if ((error = cbl_d_set_value(x, value)) != 0) {
		x->value = e->log[e->nlog - 1].old;
		e->nlog--;
		return (error);
	}
	x->flags &= ~CBL_DN_DEFAULT;
	return (0);
}

/*
 * Edit node en applied in target parent tn, op its operation unless it
 * has its own.
 */
static int
apply(struct edit *e, cbl_dnode *tn, const cbl_dnode *en, int op, int depth)
{
	cbl_dnode *x;
	int error;

	if (depth > CBL_D_DEPTH_MAX)
		return (fail(e, en, "operation-failed", ELOOP, "too deep"));
	if (en->op != 0)
		op = en->op;
	x = match(tn, en);
	switch (op) {
	case CBL_DOP_INSERT:
		if (en->where == 0)
			return (fail(e, en, "missing-attribute", EINVAL,
			    "%s: insert, but where", en->sn->name));
		/* FALLTHROUGH */
	case CBL_DOP_CREATE:
		if (x != NULL)
			return (fail(e, en, "data-exists", EEXIST,
			    "%s: there already", en->sn->name));
		/* FALLTHROUGH */
	case CBL_DOP_MERGE:
		if (x == NULL && (error = make(e, tn, en, &x)) != 0)
			return (error);
		if (en->sn->kind == CBL_YN_LEAF &&
		    (error = revalue(e, x, en->value)) != 0)
			return (error);
		if ((error = place(e, x, en)) != 0)
			return (error);
		/* Below, what is not there is made: a merge. */
		return (apply_children(e, x, en, CBL_DOP_MERGE, depth));
	case CBL_DOP_MOVE:
		if (en->where == 0)
			return (fail(e, en, "missing-attribute", EINVAL,
			    "%s: move, but where", en->sn->name));
		if (x == NULL)
			return (fail(e, en, "data-missing", ENOENT,
			    "%s: not there to move", en->sn->name));
		return (place(e, x, en));
	case CBL_DOP_REPLACE: {
		cbl_dnode *prev = NULL;
		bool had = x != NULL;

		/* The new one where the old one was, among its kind. */
		if (had) {
			prev = x->prev;
			if ((error = take(e, x)) != 0)
				return (error);
		}
		if ((error = make(e, tn, en, &x)) != 0)
			return (error);
		if (had)
			cbl_d_move_after(x, prev);
		if ((error = place(e, x, en)) != 0)
			return (error);
		return (apply_children(e, x, en, CBL_DOP_MERGE, depth));
	}
	case CBL_DOP_DELETE:
		if (x == NULL)
			return (fail(e, en, "data-missing", ENOENT,
			    "%s: not there", en->sn->name));
		/* FALLTHROUGH */
	case CBL_DOP_REMOVE:
		return (x != NULL ? take(e, x) : 0);
	case CBL_DOP_NONE:
		if (x == NULL)
			return (fail(e, en, "data-missing", ENOENT,
			    "%s: not there, and the operation is none",
			    en->sn->name));
		return (apply_children(e, x, en, CBL_DOP_NONE, depth));
	default:
		return (fail(e, en, "invalid-value", EINVAL,
		    "%s: operation %d", en->sn->name, op));
	}
}

/* The log played back, last first: the target as it was. */
static void
undo(struct edit *e)
{

	while (e->nlog > 0) {
		struct ul *u = &e->log[--e->nlog];

		switch (u->kind) {
		case UL_ADDED:
			(void)cbl_dnode_remove(u->n);
			break;
		case UL_REMOVED:
			cbl_d_reattach(u->parent, u->n, u->prev);
			break;
		case UL_VALUE:
			cbl_d_free_value(u->n);
			u->n->value = u->old;
			u->n->flags = u->oflags;
			break;
		case UL_MOVED:
			cbl_d_move_after(u->n, u->prev);
			break;
		}
	}
}

/* Done: what was taken away, and the values replaced, freed. */
static void
done(struct edit *e)
{

	for (size_t i = 0; i < e->nlog; i++) {
		struct ul *u = &e->log[i];

		if (u->kind == UL_REMOVED)
			cbl_d_free(u->n);
		else if (u->kind == UL_VALUE) {
			void *keep = u->n->value;

			u->n->value = u->old;
			cbl_d_free_value(u->n);
			u->n->value = keep;
		}
	}
	e->nlog = 0;
}

int
cbl_dtree_edit(cbl_dtree *target, const cbl_dtree *edit, int dflt,
    struct cbl_dederr *err)
{
	struct edit e = { .t = target, .err = err };
	int error = 0;

	if (err != NULL)
		memset(err, 0, sizeof(*err));
	if (target == NULL || edit == NULL ||
	    cbl_dtree_schema(target) != cbl_dtree_schema(edit) ||
	    (dflt != CBL_DOP_MERGE && dflt != CBL_DOP_REPLACE &&
	    dflt != CBL_DOP_NONE))
		return (EINVAL);
	for (const cbl_dnode *c = cbl_dtree_root(edit)->first;
	    c != NULL && error == 0; c = c->next)
		error = apply(&e, cbl_dtree_root(target), c, dflt, 0);
	if (error != 0)
		undo(&e);
	else
		done(&e);
	free(e.log);
	return (error);
}
