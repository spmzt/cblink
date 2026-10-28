/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The instance tree (cbl_data.h): nodes of the schema tables, each with
 * its parent, its siblings, its first and last child, and, by schema
 * child, where that child's instances begin and end among them, so that
 * a child goes in after its kind's last in a step.  A list's entries are
 * also in the tree's index, by parent, list and keys, a chained hash
 * table that grows.  A value is a copy in its struct member's form, what
 * it points to the tree's too; a default, parsed once, the tree's arena's.
 */

#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_data.h"
#include "cbl_dimpl.h"
#include "cbl_yimpl.h"

#define	AT(p, off)	((const void *)((const char *)(p) + (off)))
#define	WAT(p, off)	((void *)((char *)(p) + (off)))
#define	DEPTH_MAX	CBL_D_DEPTH_MAX

/* A list or a leaf-list member of a struct: its count, then its array. */
struct yarr {
	size_t		 n;
	const void	*v;
};

/*
 * Values.
 */

static bool
is_bytes(const struct cbl_ytype *t)
{

	return (t->kind == CBL_YT_BINARY || t->kind == CBL_YT_BITS ||
	    t->kind == CBL_YT_INSTANCEID);
}

static int
vcopy(const struct cbl_ytype *t, void *dst, const void *src)
{

	if (t->kind == CBL_YT_STRING) {
		const char *s = *(const char *const *)src;
		char *d;

		if ((d = strdup(s != NULL ? s : "")) == NULL)
			return (ENOMEM);
		*(char **)dst = d;
		return (0);
	}
	if (is_bytes(t)) {
		const struct cbl_bytes *b = src;
		struct cbl_bytes *d = dst;
		void *q;

		/* Not NULL, empty too: that is how a struct has it. */
		if ((q = malloc(b->len > 0 ? b->len : 1)) == NULL)
			return (ENOMEM);
		if (b->len > 0)
			memcpy(q, b->p, b->len);
		d->p = q;
		d->len = b->len;
		return (0);
	}
	if (t->kind == CBL_YT_UNION) {
		unsigned w = *(const unsigned *)src;

		if (w >= t->nmembers)
			return (EINVAL);
		memset(dst, 0, t->csize);
		*(unsigned *)dst = w;
		return (vcopy(t->members[w], WAT(dst, t->voff),
		    AT(src, t->voff)));
	}
	memcpy(dst, src, t->csize);
	return (0);
}

static void
vfree(const struct cbl_ytype *t, void *v)
{

	if (t->kind == CBL_YT_STRING)
		free(*(char **)v);
	else if (is_bytes(t))
		free((void *)(uintptr_t)((struct cbl_bytes *)v)->p);
	else if (t->kind == CBL_YT_UNION &&
	    *(const unsigned *)v < t->nmembers)
		vfree(t->members[*(const unsigned *)v], WAT(v, t->voff));
}

void *
cbl_d_vdup(const struct cbl_ytype *t, const void *value)
{
	void *v;
	int error;

	if ((v = calloc(1, t->csize > 0 ? t->csize : 1)) == NULL)
		return (NULL);
	if ((error = vcopy(t, v, value)) != 0) {
		free(v);
		errno = error;
		return (NULL);
	}
	return (v);
}

void
cbl_d_vdel(const struct cbl_ytype *t, void *v)
{

	if (v == NULL)
		return;
	vfree(t, v);
	free(v);
}

bool
cbl_dvalue_equal(const struct cbl_ytype *t, const void *a, const void *b)
{

	if (t->kind == CBL_YT_STRING) {
		const char *x = *(const char *const *)a;
		const char *y = *(const char *const *)b;

		return (strcmp(x != NULL ? x : "", y != NULL ? y : "") == 0);
	}
	if (is_bytes(t)) {
		const struct cbl_bytes *x = a, *y = b;

		return (x->len == y->len && (x->len == 0 ||
		    memcmp(x->p, y->p, x->len) == 0));
	}
	if (t->kind == CBL_YT_UNION) {
		unsigned w = *(const unsigned *)a;

		return (w == *(const unsigned *)b && w < t->nmembers &&
		    cbl_dvalue_equal(t->members[w], AT(a, t->voff),
		    AT(b, t->voff)));
	}
	if (t->kind == CBL_YT_BOOLEAN || t->kind == CBL_YT_EMPTY)
		return (*(const bool *)a == *(const bool *)b);
	return (memcmp(a, b, t->csize) == 0);
}

/* FNV-1a, 64 bits. */
static uint64_t
fnv(uint64_t h, const void *p, size_t len)
{
	const uint8_t *q = p;

	for (size_t i = 0; i < len; i++)
		h = (h ^ q[i]) * UINT64_C(0x100000001b3);
	return (h);
}

#define	FNV_BASIS	UINT64_C(0xcbf29ce484222325)

static uint64_t
vhash(uint64_t h, const struct cbl_ytype *t, const void *v)
{

	if (t->kind == CBL_YT_STRING) {
		const char *s = *(const char *const *)v;

		if (s == NULL)
			s = "";
		return (fnv(h, s, strlen(s)));
	}
	if (is_bytes(t)) {
		const struct cbl_bytes *b = v;

		h = fnv(h, &b->len, sizeof(b->len));
		return (b->len > 0 ? fnv(h, b->p, b->len) : h);
	}
	if (t->kind == CBL_YT_UNION) {
		unsigned w = *(const unsigned *)v;

		h = fnv(h, &w, sizeof(w));
		return (w < t->nmembers ? vhash(h, t->members[w],
		    AT(v, t->voff)) : h);
	}
	if (t->kind == CBL_YT_BOOLEAN || t->kind == CBL_YT_EMPTY) {
		uint8_t b = *(const bool *)v;

		return (fnv(h, &b, 1));
	}
	return (fnv(h, v, t->csize));
}

/*
 * Nodes and their places.
 */

cbl_dtree *
cbl_dtree_new(const struct cbl_yschema *s)
{
	cbl_dtree *t;
	uint32_t n = 0;

	if (s == NULL || (t = calloc(1, sizeof(*t))) == NULL)
		return (NULL);
	t->schema = s;
	t->root.tree = t;
	for (uint32_t i = 0; i < s->nmod; i++)
		n += s->mod[i]->ntop;
	if ((t->tops = calloc(n > 0 ? n : 1, sizeof(*t->tops))) == NULL ||
	    (t->arena = cbl_yarena_new()) == NULL) {
		free(t->tops);
		free(t);
		return (NULL);
	}
	for (uint32_t i = 0; i < s->nmod; i++)
		for (uint32_t j = 0; j < s->mod[i]->ntop; j++)
			t->tops[t->ntops++] = s->mod[i]->top[j];
	return (t);
}

cbl_dnode *
cbl_dtree_root(const cbl_dtree *t)
{

	return (t != NULL ? (cbl_dnode *)(uintptr_t)&t->root : NULL);
}

const struct cbl_yschema *
cbl_dtree_schema(const cbl_dtree *t)
{

	return (t != NULL ? t->schema : NULL);
}

size_t
cbl_dtree_count(const cbl_dtree *t)
{

	return (t != NULL ? t->count : 0);
}

const struct cbl_ynode *
cbl_dnode_schema(const cbl_dnode *n)
{

	return (n != NULL ? n->sn : NULL);
}

cbl_dnode *
cbl_dnode_parent(const cbl_dnode *n)
{

	return (n != NULL ? n->parent : NULL);
}

cbl_dnode *
cbl_dnode_first(const cbl_dnode *n)
{

	return (n != NULL ? n->first : NULL);
}

cbl_dnode *
cbl_dnode_last(const cbl_dnode *n)
{

	return (n != NULL ? n->last : NULL);
}

cbl_dnode *
cbl_dnode_next(const cbl_dnode *n)
{

	return (n != NULL ? n->next : NULL);
}

cbl_dnode *
cbl_dnode_prev(const cbl_dnode *n)
{

	return (n != NULL ? n->prev : NULL);
}

const void *
cbl_dnode_value(const cbl_dnode *n)
{

	return (n != NULL ? n->value : NULL);
}

uint16_t
cbl_dnode_flags(const cbl_dnode *n)
{

	return (n != NULL ? n->flags : 0);
}

int
cbl_dnode_set_op(cbl_dnode *n, int op)
{

	if (n == NULL || n->sn == NULL || op < 0 || op > CBL_DOP_MOVE ||
	    op == CBL_DOP_NONE)
		return (EINVAL);
	n->op = (uint8_t)op;
	return (0);
}

/* The types of what a point gives: a list's keys, a leaf-list's value. */
static const struct cbl_ytype *
point_type(const struct cbl_ynode *sn, uint16_t k)
{

	return (sn->kind == CBL_YN_LIST ? sn->child[sn->keys[k]]->type :
	    sn->type);
}

static uint16_t
point_n(const struct cbl_ynode *sn)
{

	return (sn->kind == CBL_YN_LIST ? sn->nkeys : 1);
}

static void
point_free(cbl_dnode *n)
{

	if (n->point == NULL)
		return;
	for (uint16_t k = 0; k < point_n(n->sn); k++)
		if (n->point[k] != NULL) {
			vfree(point_type(n->sn, k), n->point[k]);
			free(n->point[k]);
		}
	free(n->point);
	n->point = NULL;
}

int
cbl_dnode_set_where(cbl_dnode *n, int where, const void *const *point)
{
	const struct cbl_ytype *t;
	uint16_t np;
	void **p;
	int error;

	if (n == NULL || n->sn == NULL || where < 0 ||
	    where > CBL_DWHERE_AFTER ||
	    (n->sn->kind != CBL_YN_LIST && n->sn->kind != CBL_YN_LEAFLIST) ||
	    ((where == CBL_DWHERE_BEFORE || where == CBL_DWHERE_AFTER) !=
	    (point != NULL)))
		return (EINVAL);
	point_free(n);
	n->where = (uint8_t)where;
	if (point == NULL)
		return (0);
	np = point_n(n->sn);
	if ((p = calloc(np, sizeof(*p))) == NULL)
		return (ENOMEM);
	n->point = p;
	for (uint16_t k = 0; k < np; k++) {
		t = point_type(n->sn, k);
		if (point[k] == NULL ||
		    (p[k] = calloc(1, t->csize > 0 ? t->csize : 1)) == NULL ||
		    (error = vcopy(t, p[k], point[k])) != 0) {
			free(p[k]);
			p[k] = NULL;
			point_free(n);
			n->where = 0;
			return (point[k] == NULL ? EINVAL : ENOMEM);
		}
	}
	return (0);
}

int
cbl_dnode_op(const cbl_dnode *n)
{

	return (n != NULL ? n->op : 0);
}

/* The schema nodes n's children may be. */
static const struct cbl_ynode *const *
kids(const cbl_dnode *n, uint32_t *nk)
{

	/* A mount point's children are the top's (RFC 8528, the schema
	 * shared). */
	if (n->sn == NULL || (n->sn->flags & CBL_YNF_MOUNT) != 0) {
		*nk = n->tree->ntops;
		return (n->tree->tops);
	}
	*nk = n->sn->nchild;
	return (n->sn->child);
}

const struct cbl_ynode *const *
cbl_d_kids(const cbl_dtree *t, const struct cbl_ynode *sn, uint32_t *nk)
{

	if (sn == NULL || (sn->flags & CBL_YNF_MOUNT) != 0) {
		*nk = t->ntops;
		return (t->tops);
	}
	*nk = sn->nchild;
	return (sn->child);
}

/* sn's place among n's possible children, or -1: not one. */
static int64_t
kidx(const cbl_dnode *n, const struct cbl_ynode *sn)
{
	const struct cbl_ynode *const *k;
	uint32_t nk;

	k = kids(n, &nk);
	for (uint32_t i = 0; i < nk; i++)
		if (k[i] == sn)
			return (i);
	return (-1);
}

/* How many nodes n is, with all below it. */
static size_t
subtree(const cbl_dnode *n)
{
	size_t k = 1;

	for (const cbl_dnode *c = n->first; c != NULL; c = c->next)
		k += subtree(c);
	return (k);
}

/*
 * c linked as a child of parent of the i-th kind, after "after" (NULL:
 * the first of all), its kind's first or last as it falls there.
 */
static void
link_at(cbl_dnode *parent, cbl_dnode *c, uint32_t i, cbl_dnode *after)
{

	c->prev = after;
	if (after == NULL) {
		c->next = parent->first;
		parent->first = c;
	} else {
		c->next = after->next;
		after->next = c;
	}
	if (c->next != NULL)
		c->next->prev = c;
	else
		parent->last = c;
	if (after == NULL || after->sn != c->sn)
		parent->head[i] = c;
	if (c->next == NULL || c->next->sn != c->sn)
		parent->tail[i] = c;
	c->parent = parent;
}

/*
 * c, of the i-th kind of parent's children, after the last of its kind;
 * counted in the tree with all below it unless an entry's key, which is
 * counted with its entry.
 */
static int
attach(cbl_dnode *parent, cbl_dnode *c, uint32_t i, bool counted)
{
	cbl_dnode *after;
	uint32_t nk;

	if (parent->head == NULL) {
		(void)kids(parent, &nk);
		if ((parent->head = calloc(nk, sizeof(*parent->head))) ==
		    NULL || (parent->tail = calloc(nk,
		    sizeof(*parent->tail))) == NULL) {
			free(parent->head);
			parent->head = NULL;
			return (ENOMEM);
		}
	}
	after = parent->tail[i];
	for (uint32_t j = i; after == NULL && j-- > 0;)
		after = parent->tail[j];
	link_at(parent, c, i, after);
	if (counted)
		parent->tree->count += subtree(c);
	return (0);
}

/*
 * c, with all below it, out of the tree.  An entry stays in the index:
 * with no parent, no lookup finds it.
 */
static void
unlink_node(cbl_dnode *c)
{
	cbl_dnode *parent = c->parent;
	int64_t i = kidx(parent, c->sn);

	if (i >= 0) {
		if (parent->head[i] == c)
			parent->head[i] = c->next != NULL &&
			    c->next->sn == c->sn ? c->next : NULL;
		if (parent->tail[i] == c)
			parent->tail[i] = c->prev != NULL &&
			    c->prev->sn == c->sn ? c->prev : NULL;
	}
	if (c->prev != NULL)
		c->prev->next = c->next;
	else
		parent->first = c->next;
	if (c->next != NULL)
		c->next->prev = c->prev;
	else
		parent->last = c->prev;
	c->parent = c->next = c->prev = NULL;
	parent->tree->count -= subtree(c);
}

void
cbl_d_detach(cbl_dnode *n)
{

	unlink_node(n);
}

void
cbl_d_move_after(cbl_dnode *n, cbl_dnode *prev)
{
	cbl_dnode *parent = n->parent;

	if (prev == n || n->prev == prev)
		return;
	unlink_node(n);
	cbl_d_reattach(parent, n, prev);
}

void
cbl_d_reattach(cbl_dnode *parent, cbl_dnode *n, cbl_dnode *prev)
{
	int64_t i = kidx(parent, n->sn);

	/* parent had n: its head and tail are there. */
	link_at(parent, n, (uint32_t)i, prev);
	parent->tree->count += subtree(n);
}

/*
 * The index of list entries.
 */

/* The value of an entry's k-th key. */
const void *
cbl_d_key_value(const cbl_dnode *e, uint16_t k)
{
	uint32_t i = e->sn->keys[k];

	return (e->head != NULL && e->head[i] != NULL ? e->head[i]->value :
	    NULL);
}

static uint64_t
entry_hash(const cbl_dnode *parent, const struct cbl_ynode *list,
    const void *const *keys)
{
	uint64_t h = FNV_BASIS;

	h = fnv(h, &parent, sizeof(parent));
	h = fnv(h, &list, sizeof(list));
	for (uint16_t k = 0; k < list->nkeys; k++)
		h = vhash(h, list->child[list->keys[k]]->type, keys[k]);
	return (h);
}

static bool
entry_is(const cbl_dnode *e, const cbl_dnode *parent,
    const struct cbl_ynode *list, const void *const *keys)
{
	const void *v;

	if (e->parent != parent || e->sn != list)
		return (false);
	for (uint16_t k = 0; k < list->nkeys; k++)
		if ((v = cbl_d_key_value(e, k)) == NULL ||
		    !cbl_dvalue_equal(list->child[list->keys[k]]->type, v,
		    keys[k]))
			return (false);
	return (true);
}

static cbl_dnode *
index_find(const cbl_dtree *t, const cbl_dnode *parent,
    const struct cbl_ynode *list, const void *const *keys, uint64_t h)
{

	if (t->nslot == 0)
		return (NULL);
	for (cbl_dnode *e = t->slot[h & (t->nslot - 1)]; e != NULL;
	    e = e->hnext)
		if (e->hash == h && entry_is(e, parent, list, keys))
			return (e);
	return (NULL);
}

static int
index_add(cbl_dtree *t, cbl_dnode *e)
{
	cbl_dnode **slot, *x, *next;
	size_t n;

	if (t->nentries >= t->nslot) {
		n = t->nslot > 0 ? t->nslot * 2 : 64;
		if ((slot = calloc(n, sizeof(*slot))) == NULL)
			return (ENOMEM);
		for (size_t i = 0; i < t->nslot; i++)
			for (x = t->slot[i]; x != NULL; x = next) {
				next = x->hnext;
				x->hnext = slot[x->hash & (n - 1)];
				slot[x->hash & (n - 1)] = x;
			}
		free(t->slot);
		t->slot = slot;
		t->nslot = n;
	}
	e->hnext = t->slot[e->hash & (t->nslot - 1)];
	t->slot[e->hash & (t->nslot - 1)] = e;
	t->nentries++;
	return (0);
}

static void
index_remove(cbl_dtree *t, cbl_dnode *e)
{
	cbl_dnode **pp;

	if (t->nslot == 0)
		return;
	for (pp = &t->slot[e->hash & (t->nslot - 1)]; *pp != NULL;
	    pp = &(*pp)->hnext)
		if (*pp == e) {
			*pp = e->hnext;
			e->hnext = NULL;
			t->nentries--;
			return;
		}
}

static bool
indexed(const cbl_dnode *e)
{

	return (e->sn != NULL && e->sn->kind == CBL_YN_LIST &&
	    e->sn->nkeys > 0);
}

/*
 * Annotations.
 */

void
cbl_d_meta_free(cbl_dnode *n)
{
	struct cbl_dmeta *m, *next;

	for (m = n->meta; m != NULL; m = next) {
		next = m->next;
		cbl_d_vdel(m->an->type, m->value);
		free(m);
	}
	n->meta = NULL;
}

int
cbl_dnode_meta_set(cbl_dnode *n, const struct cbl_yannot *an,
    const void *value)
{
	struct cbl_dmeta **pp, *m;
	void *v = NULL;

	if (n == NULL || an == NULL || an->type == NULL || n->sn == NULL)
		return (EINVAL);
	for (pp = &n->meta; *pp != NULL && (*pp)->an->sid < an->sid;
	    pp = &(*pp)->next)
		;
	if (value != NULL && (v = cbl_d_vdup(an->type, value)) == NULL)
		return (errno != 0 ? errno : ENOMEM);
	if (*pp != NULL && (*pp)->an == an) {
		m = *pp;
		cbl_d_vdel(an->type, m->value);
		if (v != NULL) {
			m->value = v;
			return (0);
		}
		*pp = m->next;
		free(m);
		return (0);
	}
	if (v == NULL)
		return (0);
	if ((m = malloc(sizeof(*m))) == NULL) {
		cbl_d_vdel(an->type, v);
		return (ENOMEM);
	}
	m->an = an;
	m->value = v;
	m->next = *pp;
	*pp = m;
	return (0);
}

const void *
cbl_dnode_meta(const cbl_dnode *n, const struct cbl_yannot *an)
{

	for (const struct cbl_dmeta *m = n != NULL ? n->meta : NULL; m != NULL;
	    m = m->next)
		if (m->an == an)
			return (m->value);
	return (NULL);
}

const struct cbl_yannot *
cbl_dnode_meta_next(const cbl_dnode *n, const struct cbl_yannot *prev,
    const void **value)
{
	const struct cbl_dmeta *m = n != NULL ? n->meta : NULL;

	if (prev != NULL) {
		for (; m != NULL && m->an != prev; m = m->next)
			;
		if (m != NULL)
			m = m->next;
	}
	if (m == NULL)
		return (NULL);
	if (value != NULL)
		*value = m->value;
	return (m->an);
}

/*
 * Making and taking away.
 */

static void
free_node(cbl_dnode *n)
{
	cbl_dnode *c, *next;

	for (c = n->first; c != NULL; c = next) {
		next = c->next;
		free_node(c);
	}
	if (indexed(n))
		index_remove(n->tree, n);
	cbl_d_free_value(n);
	point_free(n);
	cbl_d_meta_free(n);
	free(n->head);
	free(n->tail);
	if (n != &n->tree->root)
		free(n);
}

void
cbl_dtree_free(cbl_dtree *t)
{

	if (t == NULL)
		return;
	free_node(&t->root);
	free(t->tops);
	free(t->slot);
	for (int i = 0; i < CBL_D_NDFLT; i++)
		for (struct cbl_ddflt *d = t->dflt[i], *next; d != NULL; d = next) {
			next = d->next;
			free(d);
		}
	cbl_yarena_free(t->arena);
	free(t);
}

int
cbl_dnode_remove(cbl_dnode *n)
{

	if (n == NULL || n->parent == NULL)
		return (n == NULL ? EINVAL : EPERM);
	if (n->sn->kind == CBL_YN_LEAF && (n->sn->flags & CBL_YNF_KEY) &&
	    n->parent->sn != NULL && n->parent->sn->kind == CBL_YN_LIST)
		return (EPERM);
	unlink_node(n);
	free_node(n);
	return (0);
}

void
cbl_d_free(cbl_dnode *n)
{

	free_node(n);
}

/* The (choice, case) pairs a node is in, inmost first. */
bool
cbl_d_same_case(const struct cbl_ynode *a, const struct cbl_ynode *b)
{
	const struct cbl_ychoice *ca, *cb;
	uint32_t wa, wb;

	for (ca = a->choice, wa = a->ccase; ca != NULL;
	    wa = ca->parent_case, ca = ca->parent)
		for (cb = b->choice, wb = b->ccase; cb != NULL;
		    wb = cb->parent_case, cb = cb->parent)
			if (ca == cb && wa != wb)
				return (false);
	return (true);
}

/* Whether parent has a child in another case of a choice sn is in. */
static bool
case_clash(const cbl_dnode *parent, const struct cbl_ynode *sn)
{
	const struct cbl_ynode *const *k;
	uint32_t nk;

	if (sn->choice == NULL || parent->head == NULL)
		return (false);
	k = kids(parent, &nk);
	for (uint32_t i = 0; i < nk; i++)
		if (parent->head[i] != NULL && k[i]->choice != NULL &&
		    !cbl_d_same_case(sn, k[i]))
			return (true);
	return (false);
}

static cbl_dnode *
node_new(cbl_dtree *t, const struct cbl_ynode *sn)
{
	cbl_dnode *n;

	if ((n = calloc(1, sizeof(*n))) == NULL)
		return (NULL);
	n->sn = sn;
	n->tree = t;
	return (n);
}

void
cbl_d_free_value(cbl_dnode *n)
{

	if (n->value == NULL)
		return;
	if (n->sn->type != NULL)
		vfree(n->sn->type, n->value);
	else
		free((void *)(uintptr_t)((struct cbl_bytes *)n->value)->p);
	free(n->value);
	n->value = NULL;
}

/* A leaf's or leaf-list entry's value, or anydata's bytes, copied. */
int
cbl_d_set_value(cbl_dnode *n, const void *value)
{
	const struct cbl_ytype *t = n->sn->type;
	void *v;
	int error;

	if (t == NULL) {
		const struct cbl_bytes *b = value;
		struct cbl_bytes *d;
		void *q;

		if ((d = calloc(1, sizeof(*d))) == NULL ||
		    (q = malloc(b->len > 0 ? b->len : 1)) == NULL) {
			free(d);
			return (ENOMEM);
		}
		if (b->len > 0)
			memcpy(q, b->p, b->len);
		d->p = q;
		d->len = b->len;
		v = d;
	} else {
		if ((v = calloc(1, t->csize > 0 ? t->csize : 1)) == NULL)
			return (ENOMEM);
		if ((error = vcopy(t, v, value)) != 0) {
			free(v);
			return (error);
		}
	}
	cbl_d_free_value(n);
	n->value = v;
	return (0);
}

int
cbl_dnode_add(cbl_dnode *parent, const struct cbl_ynode *sn,
    const void *value, cbl_dnode **out)
{
	cbl_dnode *n;
	int64_t i;
	int error;

	if (parent == NULL || sn == NULL || (i = kidx(parent, sn)) < 0)
		return (EINVAL);
	switch (sn->kind) {
	case CBL_YN_LIST:
		return (EINVAL);
	case CBL_YN_LEAF:
		if (value == NULL || ((sn->flags & CBL_YNF_KEY) &&
		    parent->sn != NULL && parent->sn->kind == CBL_YN_LIST))
			return (EINVAL);
		break;
	case CBL_YN_LEAFLIST:
		if (value == NULL)
			return (EINVAL);
		if ((sn->flags & CBL_YNF_CONFIG) &&
		    cbl_dnode_llentry(parent, sn, value) != NULL)
			return (EEXIST);
		break;
	case CBL_YN_ANYDATA:
	case CBL_YN_ANYXML:
		if (value == NULL)
			return (EINVAL);
		break;
	default:
		value = NULL;
		break;
	}
	if (sn->kind != CBL_YN_LEAFLIST && parent->head != NULL &&
	    parent->head[i] != NULL)
		return (EEXIST);
	if (case_clash(parent, sn))
		return (EINVAL);
	if ((n = node_new(parent->tree, sn)) == NULL)
		return (ENOMEM);
	if ((value != NULL && (error = cbl_d_set_value(n, value)) != 0) ||
	    (error = attach(parent, n, (uint32_t)i, true)) != 0) {
		free_node(n);
		return (error);
	}
	if (out != NULL)
		*out = n;
	return (0);
}

int
cbl_dnode_add_entry(cbl_dnode *parent, const struct cbl_ynode *list,
    const void *const *keys, cbl_dnode **out)
{
	cbl_dnode *e, *k;
	int64_t i;
	int error;

	if (parent == NULL || list == NULL || list->kind != CBL_YN_LIST ||
	    (list->nkeys > 0 && keys == NULL) || (i = kidx(parent, list)) < 0)
		return (EINVAL);
	for (uint16_t j = 0; j < list->nkeys; j++)
		if (keys[j] == NULL)
			return (EINVAL);
	if (case_clash(parent, list))
		return (EINVAL);
	if ((e = node_new(parent->tree, list)) == NULL)
		return (ENOMEM);
	if (list->nkeys > 0) {
		e->hash = entry_hash(parent, list, keys);
		if (index_find(parent->tree, parent, list, keys, e->hash) !=
		    NULL) {
			free(e);
			return (EEXIST);
		}
	}
	for (uint16_t j = 0; j < list->nkeys; j++) {
		uint32_t ki = list->keys[j];

		/* free_node() counts each key it frees off the tree. */
		if ((k = node_new(parent->tree, list->child[ki])) == NULL ||
		    (error = cbl_d_set_value(k, keys[j])) != 0 ||
		    (error = attach(e, k, ki, false)) != 0) {
			if (k != NULL)
				free_node(k);
			free_node(e);
			return (k == NULL ? ENOMEM : error);
		}
	}
	if ((error = attach(parent, e, (uint32_t)i, true)) != 0 ||
	    (list->nkeys > 0 && (error = index_add(parent->tree, e)) != 0)) {
		if (e->parent != NULL)
			unlink_node(e);
		free_node(e);
		return (error);
	}
	if (out != NULL)
		*out = e;
	return (0);
}

int
cbl_dnode_set(cbl_dnode *n, const void *value)
{
	cbl_dnode *x;

	if (n == NULL || value == NULL || n->sn == NULL ||
	    (n->sn->kind != CBL_YN_LEAF && n->sn->kind != CBL_YN_LEAFLIST))
		return (EINVAL);
	if ((n->sn->flags & CBL_YNF_KEY) && n->parent->sn != NULL &&
	    n->parent->sn->kind == CBL_YN_LIST)
		return (EPERM);
	if (n->sn->kind == CBL_YN_LEAFLIST &&
	    (n->sn->flags & CBL_YNF_CONFIG) &&
	    (x = cbl_dnode_llentry(n->parent, n->sn, value)) != NULL &&
	    x != n)
		return (EEXIST);
	n->flags &= ~CBL_DN_DEFAULT;
	return (cbl_d_set_value(n, value));
}

/*
 * Finding.
 */

cbl_dnode *
cbl_dnode_child(const cbl_dnode *n, const struct cbl_ynode *sn)
{
	int64_t i;

	if (n == NULL || n->head == NULL || (i = kidx(n, sn)) < 0)
		return (NULL);
	return (n->head[i]);
}

cbl_dnode *
cbl_dnode_entry(const cbl_dnode *parent, const struct cbl_ynode *list,
    const void *const *keys)
{

	if (parent == NULL || list == NULL || list->kind != CBL_YN_LIST ||
	    list->nkeys == 0 || keys == NULL)
		return (NULL);
	return (index_find(parent->tree, parent, list, keys,
	    entry_hash(parent, list, keys)));
}

cbl_dnode *
cbl_dnode_llentry(const cbl_dnode *parent, const struct cbl_ynode *ll,
    const void *value)
{

	if (ll == NULL || ll->kind != CBL_YN_LEAFLIST || value == NULL)
		return (NULL);
	for (cbl_dnode *x = cbl_dnode_child(parent, ll);
	    x != NULL && x->sn == ll; x = x->next)
		if (cbl_dvalue_equal(ll->type, x->value, value))
			return (x);
	return (NULL);
}

/*
 * Defaults.
 */

static const void *
dflt_value(cbl_dtree *t, const struct cbl_ynode *sn, uint16_t k)
{
	struct cbl_ddflt *d;
	size_t b = ((uintptr_t)sn >> 4 ^ k) % CBL_D_NDFLT;
	void *v;

	for (d = t->dflt[b]; d != NULL; d = d->next)
		if (d->sn == sn && d->k == k)
			return (d->v);
	if ((v = cbl_yarena_alloc(t->arena, sn->type->csize > 0 ?
	    sn->type->csize : 1)) == NULL ||
	    cbl_ydefault_parse(sn, k, v, t->arena) != 0 ||
	    (d = malloc(sizeof(*d))) == NULL)
		return (NULL);
	d->sn = sn;
	d->k = k;
	d->v = v;
	d->next = t->dflt[b];
	t->dflt[b] = d;
	return (v);
}

/*
 * Whether sn's case is n's, for each choice it is in: the case n has a
 * node of, or where n has none, the choice's default case.
 */
static bool
case_applies(const cbl_dnode *n, const struct cbl_ynode *sn)
{
	const struct cbl_ynode *const *k;
	const struct cbl_ychoice *c;
	uint32_t want, nk;

	if (sn->choice == NULL)
		return (true);
	k = kids(n, &nk);
	for (c = sn->choice, want = sn->ccase; c != NULL;
	    want = c->parent_case, c = c->parent) {
		bool any = false;

		for (uint32_t i = 0; n->head != NULL && i < nk && !any; i++) {
			const struct cbl_ychoice *xc;
			uint32_t xw;

			if (n->head[i] == NULL)
				continue;
			for (xc = k[i]->choice, xw = k[i]->ccase; xc != NULL;
			    xw = xc->parent_case, xc = xc->parent)
				if (xc == c) {
					if (xw != want)
						return (false);
					any = true;
					break;
				}
		}
		if (!any && c->dflt != (int32_t)want)
			return (false);
	}
	return (true);
}

const void *
cbl_dnode_leaf(const cbl_dnode *n, const struct cbl_ynode *leaf,
    bool *isdflt)
{
	cbl_dnode *x;

	if (isdflt != NULL)
		*isdflt = false;
	if (n == NULL || leaf == NULL || leaf->kind != CBL_YN_LEAF)
		return (NULL);
	if ((x = cbl_dnode_child(n, leaf)) != NULL) {
		if (isdflt != NULL)
			*isdflt = (x->flags & CBL_DN_DEFAULT) != 0;
		return (x->value);
	}
	if (leaf->ndflt == 0 || kidx(n, leaf) < 0 || !case_applies(n, leaf))
		return (NULL);
	if (isdflt != NULL)
		*isdflt = true;
	return (dflt_value(n->tree, leaf, 0));
}

static ssize_t
d_node(cbl_dnode *n, int depth)
{
	const struct cbl_ynode *const *k;
	cbl_dnode *x, *next;
	const void *v;
	uint32_t nk;
	ssize_t made = 0, r;
	int error;

	if (depth > DEPTH_MAX) {
		errno = ELOOP;
		return (-1);
	}
	k = kids(n, &nk);
	for (uint32_t i = 0; i < nk; i++) {
		const struct cbl_ynode *sn = k[i];

		x = n->head != NULL ? n->head[i] : NULL;
		switch (sn->kind) {
		case CBL_YN_LEAF:
			if (x != NULL || sn->ndflt == 0 ||
			    !case_applies(n, sn) ||
			    (v = dflt_value(n->tree, sn, 0)) == NULL)
				break;
			if ((error = cbl_dnode_add(n, sn, v, &x)) != 0) {
				errno = error;
				return (-1);
			}
			x->flags |= CBL_DN_DEFAULT;
			made++;
			break;
		case CBL_YN_LEAFLIST:
			if (x != NULL || sn->ndflt == 0 ||
			    !case_applies(n, sn))
				break;
			for (uint16_t j = 0; j < sn->ndflt; j++) {
				if ((v = dflt_value(n->tree, sn, j)) == NULL)
					break;
				if ((error = cbl_dnode_add(n, sn, v, &x)) !=
				    0) {
					errno = error;
					return (-1);
				}
				x->flags |= CBL_DN_DEFAULT;
				made++;
			}
			break;
		case CBL_YN_CONTAINER:
			if (x == NULL) {
				/* A non-presence container is there in
				 * effect: made if it holds a default. */
				if ((sn->flags & CBL_YNF_PRESENCE) ||
				    !case_applies(n, sn))
					break;
				if ((error = cbl_dnode_add(n, sn, NULL,
				    &x)) != 0) {
					errno = error;
					return (-1);
				}
				x->flags |= CBL_DN_DEFAULT;
				if ((r = d_node(x, depth + 1)) <= 0) {
					(void)cbl_dnode_remove(x);
					if (r < 0)
						return (-1);
					break;
				}
				made += r;
				break;
			}
			/* FALLTHROUGH */
		case CBL_YN_LIST:
		case CBL_YN_RPC:
		case CBL_YN_ACTION:
		case CBL_YN_INPUT:
		case CBL_YN_OUTPUT:
		case CBL_YN_NOTIF:
		case CBL_YN_STRUCTURE:
			for (; x != NULL && x->sn == sn; x = next) {
				next = x->next;
				if ((r = d_node(x, depth + 1)) < 0)
					return (-1);
				made += r;
			}
			break;
		default:
			break;
		}
	}
	return (made);
}

ssize_t
cbl_dtree_defaults(cbl_dnode *n)
{

	ssize_t made, gone;

	if (n == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if ((made = d_node(n, 0)) < 0 || (gone = cbl_d_prune_defaults(n)) < 0)
		return (-1);
	return (made - gone);
}

static bool
is_default(cbl_dnode *x, int mode)
{
	const void *v;

	if ((x->flags & CBL_DN_DEFAULT) != 0)
		return (true);
	return (mode == CBL_WD_TRIM && x->sn->ndflt > 0 &&
	    (v = dflt_value(x->tree, x->sn, 0)) != NULL &&
	    cbl_dvalue_equal(x->sn->type, x->value, v));
}

/* A leaf-list's run of entries from x: all its defaults, as the mode
 * sees them; *after, the node after the run. */
static bool
run_default(cbl_dnode *x, int mode, cbl_dnode **after)
{
	const struct cbl_ynode *sn = x->sn;
	bool made = true, same = true;
	uint16_t j = 0;

	for (; x != NULL && x->sn == sn; x = x->next, j++) {
		const void *v;

		if ((x->flags & CBL_DN_DEFAULT) == 0)
			made = false;
		if (j >= sn->ndflt ||
		    (v = dflt_value(x->tree, sn, j)) == NULL ||
		    !cbl_dvalue_equal(sn->type, x->value, v))
			same = false;
	}
	*after = x;
	return (made || (mode == CBL_WD_TRIM && same && j == sn->ndflt));
}

static int
wd_node(cbl_dnode *n, int mode, int depth)
{
	cbl_dnode *x, *next, *y;
	int error;

	if (depth > DEPTH_MAX)
		return (ELOOP);
	for (x = n->first; x != NULL; x = next) {
		next = x->next;
		switch (x->sn->kind) {
		case CBL_YN_LEAF:
			/* A key stays (EPERM), its default or not. */
			if (is_default(x, mode) && (error =
			    cbl_dnode_remove(x)) != 0 && error != EPERM)
				return (error);
			break;
		case CBL_YN_LEAFLIST:
			if (!run_default(x, mode, &next))
				break;
			for (; x != next; x = y) {
				y = x->next;
				if ((error = cbl_dnode_remove(x)) != 0)
					return (error);
			}
			break;
		case CBL_YN_CONTAINER:
		case CBL_YN_LIST:
		case CBL_YN_RPC:
		case CBL_YN_ACTION:
		case CBL_YN_INPUT:
		case CBL_YN_OUTPUT:
		case CBL_YN_NOTIF:
		case CBL_YN_STRUCTURE:
			if ((error = wd_node(x, mode, depth + 1)) != 0)
				return (error);
			if (x->sn->kind == CBL_YN_CONTAINER &&
			    (x->sn->flags & CBL_YNF_PRESENCE) == 0 &&
			    x->first == NULL &&
			    (error = cbl_dnode_remove(x)) != 0)
				return (error);
			break;
		default:
			break;
		}
	}
	return (0);
}

int
cbl_dtree_with_defaults(cbl_dnode *n, int mode)
{
	int error;

	if (n == NULL || (mode != CBL_WD_REPORT_ALL && mode != CBL_WD_TRIM &&
	    mode != CBL_WD_EXPLICIT)) {
		errno = EINVAL;
		return (-1);
	}
	if (mode == CBL_WD_REPORT_ALL)
		return (cbl_dtree_defaults(n) < 0 ? -1 : 0);
	if ((error = wd_node(n, mode, 0)) != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

/*
 * Structs.
 */

static int	fill(cbl_dnode *, const struct cbl_ynode *const *, uint32_t,
		    const void *, int);

static int
from_struct(cbl_dnode *parent, const struct cbl_ynode *sn, const void *p,
    cbl_dnode **out, int depth)
{
	const void *keys[UINT8_MAX];
	cbl_dnode *x;
	int error;

	if (p == NULL || sn->size == 0 || depth > DEPTH_MAX)
		return (depth > DEPTH_MAX ? ELOOP : EINVAL);
	if (sn->kind == CBL_YN_LIST) {
		if (sn->nkeys > nitems(keys))
			return (EINVAL);
		for (uint16_t k = 0; k < sn->nkeys; k++)
			keys[k] = AT(p, sn->child[sn->keys[k]]->off);
		error = cbl_dnode_add_entry(parent, sn, keys, &x);
	} else
		error = cbl_dnode_add(parent, sn, NULL, &x);
	if (error != 0)
		return (error);
	if ((error = fill(x, sn->child, sn->nchild, p, depth)) != 0) {
		(void)cbl_dnode_remove(x);
		return (error);
	}
	if (out != NULL)
		*out = x;
	return (0);
}

/* The members of struct p that are there, children of x. */
static int
fill(cbl_dnode *x, const struct cbl_ynode *const *ch, uint32_t nch,
    const void *p, int depth)
{
	const struct yarr *arr;
	int error = 0;

	for (uint32_t i = 0; i < nch && error == 0; i++) {
		const struct cbl_ynode *c = ch[i];

		if (c->off == CBL_YOFF_NONE || !cbl_ypresent(c, p))
			continue;
		switch (c->kind) {
		case CBL_YN_CONTAINER:
			error = from_struct(x, c, *(const void *const *)
			    AT(p, c->off), NULL, depth + 1);
			break;
		case CBL_YN_LIST:
			arr = AT(p, c->off);
			for (size_t k = 0; k < arr->n && error == 0; k++)
				error = from_struct(x, c, AT(arr->v,
				    k * c->size), NULL, depth + 1);
			break;
		case CBL_YN_LEAF:
			/* An entry's keys came with it. */
			if ((c->flags & CBL_YNF_KEY) && x->sn != NULL &&
			    x->sn->kind == CBL_YN_LIST)
				break;
			error = cbl_dnode_add(x, c, AT(p, c->off), NULL);
			break;
		case CBL_YN_LEAFLIST:
			arr = AT(p, c->off);
			for (size_t k = 0; k < arr->n && error == 0; k++)
				error = cbl_dnode_add(x, c, AT(arr->v,
				    k * c->type->csize), NULL);
			break;
		case CBL_YN_ANYDATA:
		case CBL_YN_ANYXML:
			error = cbl_dnode_add(x, c, AT(p, c->off), NULL);
			break;
		default:
			break;
		}
	}
	return (error);
}

int
cbl_dnode_from_struct(cbl_dnode *parent, const struct cbl_ynode *sn,
    const void *p, cbl_dnode **out)
{

	if (parent == NULL || sn == NULL)
		return (EINVAL);
	return (from_struct(parent, sn, p, out, 0));
}

static int	put_members(const cbl_dnode *, const cbl_dnode *, void *,
		    cbl_yarena *, int);

static int
to_struct(const cbl_dnode *n, void *p, cbl_yarena *a, int depth)
{

	if (n->sn == NULL || n->sn->size == 0)
		return (EINVAL);
	memset(p, 0, n->sn->size);
	return (put_members(n->first, NULL, p, a, depth));
}

/* Siblings from first to end (not it) into struct p, by their members. */
static int
put_members(const cbl_dnode *first, const cbl_dnode *end, void *p,
    cbl_yarena *a, int depth)
{
	const cbl_dnode *c, *g;
	struct yarr *arr;
	size_t cnt, k;
	uint8_t *v;
	void *q;
	int error;

	if (depth > DEPTH_MAX)
		return (ELOOP);
	for (c = first; c != end;) {
		const struct cbl_ynode *cs = c->sn;

		if (cs->off == CBL_YOFF_NONE) {
			c = c->next;
			continue;
		}
		if ((error = cbl_yset_case(cs, p)) != 0)
			return (error);
		switch (cs->kind) {
		case CBL_YN_CONTAINER:
			if ((q = cbl_yarena_alloc(a, cs->size)) == NULL)
				return (ENOMEM);
			if ((error = to_struct(c, q, a, depth + 1)) != 0)
				return (error);
			*(void **)WAT(p, cs->off) = q;
			c = c->next;
			break;
		case CBL_YN_LIST:
		case CBL_YN_LEAFLIST:
			for (cnt = 0, g = c; g != end && g->sn == cs;
			    g = g->next)
				cnt++;
			k = cs->kind == CBL_YN_LIST ? cs->size :
			    cs->type->csize;
			if ((v = cbl_yarena_alloc(a, cnt * k)) == NULL)
				return (ENOMEM);
			for (size_t j = 0; j < cnt; j++, c = c->next) {
				if (cs->kind == CBL_YN_LEAFLIST)
					memcpy(v + j * k, c->value, k);
				else if ((error = to_struct(c, v + j * k, a,
				    depth + 1)) != 0)
					return (error);
			}
			arr = WAT(p, cs->off);
			arr->n = cnt;
			arr->v = v;
			break;
		case CBL_YN_LEAF:
			memcpy(WAT(p, cs->off), c->value, cs->type->csize);
			if (cs->hoff != CBL_YOFF_NONE)
				*(bool *)WAT(p, cs->hoff) = true;
			c = c->next;
			break;
		case CBL_YN_ANYDATA:
		case CBL_YN_ANYXML:
			memcpy(WAT(p, cs->off), c->value,
			    sizeof(struct cbl_bytes));
			c = c->next;
			break;
		default:
			c = c->next;
			break;
		}
	}
	return (0);
}

int
cbl_dnode_to_struct(const cbl_dnode *n, void *p, cbl_yarena *a)
{

	if (n == NULL || p == NULL || a == NULL)
		return (EINVAL);
	return (to_struct(n, p, a, 0));
}

int
cbl_dtree_from_module(cbl_dtree *t, const struct cbl_ymodule *m,
    const void *p)
{

	if (t == NULL || m == NULL || p == NULL || m->size == 0)
		return (EINVAL);
	return (fill(&t->root, m->top, m->ntop, p, 0));
}

int
cbl_dtree_to_module(const cbl_dtree *t, const struct cbl_ymodule *m,
    void *p, cbl_yarena *a)
{
	const cbl_dnode *first, *end;

	if (t == NULL || m == NULL || p == NULL || a == NULL || m->size == 0)
		return (EINVAL);
	memset(p, 0, m->size);
	/* The root's children are by module: m's are one run of them. */
	for (first = t->root.first; first != NULL && first->sn->module != m;
	    first = first->next)
		;
	for (end = first; end != NULL && end->sn->module == m; end = end->next)
		;
	return (put_members(first, end, p, a, 0));
}

/*
 * YANG-CBOR.
 */

int
cbl_dnode_decode(cbl_dnode *parent, const struct cbl_ynode *sn,
    const void *data, size_t len, int flags, char *why, size_t whylen,
    cbl_dnode **out)
{

	if (parent == NULL || sn == NULL)
		return (EINVAL);
	return (cbl_d_decode(parent, sn, data, len, flags, why, whylen, out));
}

int
cbl_dnode_encode(const cbl_dnode *n, struct cbl_ybuf *b)
{

	if (n == NULL || n->sn == NULL)
		return (EINVAL);
	return (cbl_d_encode(n, b));
}

/* Into an empty tree; what was read taken out again on failure. */
int
cbl_dtree_decode(cbl_dtree *t, const void *data, size_t len, int flags,
    char *why, size_t whylen)
{
	int error;

	if (t == NULL)
		return (EINVAL);
	if (t->root.first != NULL)
		return (EEXIST);
	if ((error = cbl_d_decode(&t->root, NULL, data, len, flags, why,
	    whylen, NULL)) != 0)
		while (t->root.first != NULL)
			(void)cbl_dnode_remove(t->root.first);
	return (error);
}

int
cbl_dtree_encode(const cbl_dtree *t, struct cbl_ybuf *b)
{

	if (t == NULL)
		return (EINVAL);
	return (cbl_d_encode(&t->root, b));
}
