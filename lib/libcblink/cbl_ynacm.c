/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * NACM, RFC 8341: who a request is for, and what that user may do.
 *
 * The user is the peer's, or the one a trusted peer says it asks for
 * (cblink:user beside the request), as the program's fn decides
 * (cbl_ctx_set_user()); root on a unix socket is, by default, the
 * recovery session, which nothing holds back.
 *
 * The rules are the program's: its nacm container of ietf-netconf-acm,
 * read through the server's get handler as a tree and kept, compiled,
 * until the program or an EDIT says they changed.  A check is section
 * 3.4's: the rule-lists of the user's groups in order, each one's rules
 * in order, the first rule whose module, kind, name or path and access
 * operation match deciding; with none, a node nacm:default-deny-all
 * marks (or one above it) is denied, and for a write one
 * nacm:default-deny-write marks, else the default of the access (read,
 * write or exec).  enable-nacm false lets everything through.
 */

#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <pwd.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_data.h"
#include "cbl_dimpl.h"
#include "cbl_impl.h"
#include "cbl_schema.h"
#include "cbl_yimpl.h"
#include "cbl_ymod.h"

/* RFC 8341's access-operations bits. */
#define	A_CREATE	0x01
#define	A_READ		0x02
#define	A_UPDATE	0x04
#define	A_DELETE	0x08
#define	A_EXEC		0x10
#define	A_ALL		0x1f
#define	A_WRITE		(A_CREATE | A_UPDATE | A_DELETE)

/* What a rule is about: its rule-type case, or any (none given). */
enum rtype {
	RT_ANY,
	RT_RPC,
	RT_NOTIF,
	RT_PATH,
};

struct nrule {
	char		*module;	/* "*": any */
	enum rtype	 type;
	char		*name;		/* rpc's or notification's, "*": any */
	cbl_dnacm_path	*path;		/* RT_PATH; NULL: it never matches */
	unsigned	 ops;
	bool		 permit;
};

struct nlist {
	char		**groups;	/* "*": all */
	size_t		 ngroups;
	struct nrule	*rules;
	size_t		 nrules;
};

struct ngroup {
	char		*name;
	char		**users;
	size_t		 nusers;
};

struct cbl_ynacm {
	atomic_uint	 refs;
	bool		 enable;
	bool		 rd, wr, ex;	/* the defaults: true, permit */
	bool		 broken;	/* not read: all denied */
	struct ngroup	*groups;
	size_t		 ngroups;
	struct nlist	*lists;
	size_t		 nlists;
};

/* What is checked. */
enum tkind {
	T_RPC,
	T_NOTIF,
	T_DATA,
};

struct target {
	enum tkind		 kind;
	const char		*module;
	const char		*name;	/* an rpc's or a notification's */
	const cbl_dnode		*dn;	/* an instance, or NULL */
	const struct cbl_ynode	*sn;	/* its schema node, or NULL */
	unsigned		 deny;	/* CBL_YNF_DENY_* on it or above */
};

/* The user's groups, those the rules name, during one check. */
struct who_groups {
	const char	**v;
	size_t		 n;
};

static void
nacm_free(struct cbl_ynacm *c)
{

	if (c == NULL)
		return;
	for (size_t i = 0; i < c->ngroups; i++) {
		free(c->groups[i].name);
		for (size_t j = 0; j < c->groups[i].nusers; j++)
			free(c->groups[i].users[j]);
		free(c->groups[i].users);
	}
	free(c->groups);
	for (size_t i = 0; i < c->nlists; i++) {
		for (size_t j = 0; j < c->lists[i].ngroups; j++)
			free(c->lists[i].groups[j]);
		free(c->lists[i].groups);
		for (size_t j = 0; j < c->lists[i].nrules; j++) {
			free(c->lists[i].rules[j].module);
			free(c->lists[i].rules[j].name);
			cbl_dnacm_path_free(c->lists[i].rules[j].path);
		}
		free(c->lists[i].rules);
	}
	free(c->lists);
	free(c);
}

static void
nacm_rele(struct cbl_ynacm *c)
{

	if (c != NULL && atomic_fetch_sub(&c->refs, 1) == 1)
		nacm_free(c);
}

/* A child of n by its schema node's name, the first; or NULL. */
static const cbl_dnode *
kid(const cbl_dnode *n, const char *name)
{

	for (const cbl_dnode *c = n != NULL ? cbl_dnode_first(n) : NULL;
	    c != NULL; c = cbl_dnode_next(c))
		if (strcmp(cbl_dnode_schema(c)->name, name) == 0)
			return (c);
	return (NULL);
}

/* A leaf's value as its canonical text, malloc'd; dflt where it has none. */
static char *
text(const struct cbl_yschema *s, const cbl_dnode *n, const char *dflt)
{
	char *out = NULL;

	if (n == NULL || cbl_dnode_value(n) == NULL)
		return (dflt != NULL ? strdup(dflt) : NULL);
	if (cbl_d_vstring(s, cbl_dnode_schema(n)->type, cbl_dnode_value(n),
	    &out) != 0)
		return (NULL);
	return (out);
}

/* A leaf that says permit or deny, true or false: whether it says yes. */
static bool
says(const struct cbl_yschema *s, const cbl_dnode *n, const char *yes,
    bool dflt)
{
	char *t;
	bool v;

	if (n == NULL)
		return (dflt);
	if ((t = text(s, n, NULL)) == NULL)
		return (dflt);
	v = strcmp(t, yes) == 0;
	free(t);
	return (v);
}

/* access-operations' text: "*", or the bits' names. */
static unsigned
ops_of(const char *t)
{
	static const struct {
		const char	*name;
		unsigned	 bit;
	} b[] = {
		{ "create", A_CREATE }, { "read", A_READ },
		{ "update", A_UPDATE }, { "delete", A_DELETE },
		{ "exec", A_EXEC },
	};
	unsigned ops = 0;
	size_t len;

	if (t == NULL || strcmp(t, "*") == 0)
		return (A_ALL);
	while (*t != '\0') {
		t += strspn(t, " \t");
		len = strcspn(t, " \t");
		for (size_t i = 0; i < nitems(b); i++)
			if (strlen(b[i].name) == len && strncmp(t, b[i].name,
			    len) == 0)
				ops |= b[i].bit;
		t += len;
	}
	return (ops);
}

/* The values of a leaf-list named name under n, malloc'd. */
static int
values(const struct cbl_yschema *s, const cbl_dnode *n, const char *name,
    char ***vp, size_t *np)
{
	char **v = NULL, **nv, *t;
	size_t k = 0;

	*vp = NULL;
	*np = 0;
	for (const cbl_dnode *c = n != NULL ? cbl_dnode_first(n) : NULL;
	    c != NULL; c = cbl_dnode_next(c)) {
		if (strcmp(cbl_dnode_schema(c)->name, name) != 0)
			continue;
		if ((t = text(s, c, NULL)) == NULL ||
		    (nv = reallocarray(v, k + 1, sizeof(*v))) == NULL) {
			free(t);
			for (size_t i = 0; i < k; i++)
				free(v[i]);
			free(v);
			return (ENOMEM);
		}
		v = nv;
		v[k++] = t;
	}
	*vp = v;
	*np = k;
	return (0);
}

/* How many children of n are named name. */
static size_t
count(const cbl_dnode *n, const char *name)
{
	size_t k = 0;

	for (const cbl_dnode *c = n != NULL ? cbl_dnode_first(n) : NULL;
	    c != NULL; c = cbl_dnode_next(c))
		if (strcmp(cbl_dnode_schema(c)->name, name) == 0)
			k++;
	return (k);
}

/* A rule from its entry; its path compiled for schema s.  A path that
 * does not compile (a module not served) never matches. */
static int
rule_of(const struct cbl_yschema *s, const cbl_dnode *e, struct nrule *r)
{
	const cbl_dnode *x;
	char *t, why[128];

	r->module = text(s, kid(e, "module-name"), "*");
	r->permit = says(s, kid(e, "action"), "permit", false);
	t = text(s, kid(e, "access-operations"), "*");
	r->ops = ops_of(t);
	free(t);
	if ((x = kid(e, "rpc-name")) != NULL) {
		r->type = RT_RPC;
		r->name = text(s, x, NULL);
	} else if ((x = kid(e, "notification-name")) != NULL) {
		r->type = RT_NOTIF;
		r->name = text(s, x, NULL);
	} else if ((x = kid(e, "path")) != NULL) {
		r->type = RT_PATH;
		if ((t = text(s, x, NULL)) == NULL)
			return (ENOMEM);
		r->path = cbl_dnacm_path_new(s, t, why, sizeof(why));
		free(t);
	} else
		r->type = RT_ANY;
	if (r->module == NULL || ((r->type == RT_RPC ||
	    r->type == RT_NOTIF) && r->name == NULL))
		return (ENOMEM);
	return (0);
}

/* The rules from the nacm container's tree. */
static int
parse(const struct cbl_yschema *s, const cbl_dnode *nacm,
    struct cbl_ynacm *c)
{
	const cbl_dnode *gs, *e, *r;
	size_t i, j;
	int error;

	c->enable = says(s, kid(nacm, "enable-nacm"), "true", true);
	c->rd = says(s, kid(nacm, "read-default"), "permit", true);
	c->wr = says(s, kid(nacm, "write-default"), "permit", false);
	c->ex = says(s, kid(nacm, "exec-default"), "permit", true);
	gs = kid(nacm, "groups");
	if ((c->ngroups = count(gs, "group")) > 0 &&
	    (c->groups = calloc(c->ngroups, sizeof(*c->groups))) == NULL)
		return (ENOMEM);
	i = 0;
	for (e = gs != NULL ? cbl_dnode_first(gs) : NULL; e != NULL;
	    e = cbl_dnode_next(e)) {
		if (strcmp(cbl_dnode_schema(e)->name, "group") != 0)
			continue;
		if ((c->groups[i].name = text(s, kid(e, "name"), NULL)) ==
		    NULL || (error = values(s, e, "user-name",
		    &c->groups[i].users, &c->groups[i].nusers)) != 0)
			return (ENOMEM);
		i++;
	}
	if ((c->nlists = count(nacm, "rule-list")) > 0 &&
	    (c->lists = calloc(c->nlists, sizeof(*c->lists))) == NULL)
		return (ENOMEM);
	i = 0;
	for (e = cbl_dnode_first(nacm); e != NULL; e = cbl_dnode_next(e)) {
		struct nlist *l;

		if (strcmp(cbl_dnode_schema(e)->name, "rule-list") != 0)
			continue;
		l = &c->lists[i++];
		if ((error = values(s, e, "group", &l->groups, &l->ngroups)) !=
		    0)
			return (error);
		if ((l->nrules = count(e, "rule")) > 0 &&
		    (l->rules = calloc(l->nrules, sizeof(*l->rules))) == NULL)
			return (ENOMEM);
		j = 0;
		for (r = cbl_dnode_first(e); r != NULL; r = cbl_dnode_next(r))
			if (strcmp(cbl_dnode_schema(r)->name, "rule") == 0 &&
			    (error = rule_of(s, r, &l->rules[j++])) != 0)
				return (error);
	}
	return (0);
}

/*
 * The server's nacm container, its handler and schema; false where no
 * server has one, and NACM is off.
 */
static bool
nacm_node(cbl_ctx *ctx, struct cbl_yfound *f)
{
	bool found = false;

	pthread_rwlock_rdlock(&ctx->famlock);
	for (size_t i = 0; !found && i < ctx->nysrv; i++) {
		const struct cbl_yschema *s = ctx->ysrv[i].srv->schema;

		for (uint32_t m = 0; !found && m < s->nmod; m++) {
			if (strcmp(s->mod[m]->name, "ietf-netconf-acm") != 0)
				continue;
			for (uint32_t k = 0; k < s->mod[m]->ntop; k++)
				if (strcmp(s->mod[m]->top[k]->name, "nacm") == 0)
					found = cbl_yfind(ctx,
					    s->mod[m]->top[k]->sid, f) &&
					    f->h != NULL && f->h->get != NULL;
		}
	}
	pthread_rwlock_unlock(&ctx->famlock);
	return (found);
}

/* The rules read anew, on a request of conn's (NULL: none). */
static struct cbl_ynacm *
nacm_read(cbl_conn *conn, const struct cbl_yfound *f)
{
	struct cbl_ybuf b = { NULL, 0, 0 };
	struct cbl_ynacm *c;
	struct cbl_req r;
	cbl_dtree *t = NULL;
	cbl_yarena *a;
	void *data;
	char why[128];
	int error = ENOMEM;

	if ((c = calloc(1, sizeof(*c))) == NULL)
		return (NULL);
	atomic_init(&c->refs, 1);
	c->enable = true;
	c->rd = c->ex = true;
	memset(&r, 0, sizeof(r));
	r.conn = conn;
	r.recovery = true;
	atomic_init(&r.refs, 1);
	r.yarg = f->arg;
	if ((a = cbl_yarena_new()) != NULL &&
	    (data = cbl_yarena_alloc(a, f->n->module->size)) != NULL &&
	    (error = f->h->get(&r, data, a)) == 0) {
		if (!cbl_ymember_present(f->n, data))
			error = 0;	/* none: the defaults */
		else if ((t = cbl_dtree_new(f->srv->schema)) == NULL)
			error = ENOMEM;
		else if ((error = cbl_yencode_member(f->n, data, &b)) == 0 &&
		    (error = cbl_dnode_decode(cbl_dtree_root(t), f->n, b.p,
		    b.len, 0, why, sizeof(why), NULL)) == 0 &&
		    kid(cbl_dtree_root(t), "nacm") != NULL)
			error = parse(f->srv->schema, kid(cbl_dtree_root(t),
			    "nacm"), c);
	}
	cbl_ybuf_free(&b);
	cbl_dtree_free(t);
	cbl_yarena_free(a);
	free(r.err_msg);
	if (error != 0) {
		/* Not known: nothing but the recovery session. */
		nacm_free(c);
		if ((c = calloc(1, sizeof(*c))) == NULL)
			return (NULL);
		atomic_init(&c->refs, 1);
		c->enable = true;
		c->broken = true;
	}
	return (c);
}

/* The rules, a reference; NULL where NACM is off. */
static struct cbl_ynacm *
nacm_get(cbl_ctx *ctx, cbl_conn *conn)
{
	struct cbl_ynacm *c, *old;
	struct cbl_yfound f;
	uint64_t gen;

	if (!nacm_node(ctx, &f))
		return (NULL);
	pthread_mutex_lock(&ctx->nacmlock);
	if (ctx->nacm != NULL && ctx->nacmread == ctx->nacmgen) {
		c = ctx->nacm;
		atomic_fetch_add(&c->refs, 1);
		pthread_mutex_unlock(&ctx->nacmlock);
		return (c);
	}
	gen = ctx->nacmgen;
	pthread_mutex_unlock(&ctx->nacmlock);
	/* Read without the lock: the handler may take its time. */
	if ((c = nacm_read(conn, &f)) == NULL)
		return (NULL);
	pthread_mutex_lock(&ctx->nacmlock);
	if (ctx->nacmgen == gen) {
		old = ctx->nacm;
		ctx->nacm = c;
		ctx->nacmread = gen;
		atomic_fetch_add(&c->refs, 1);
		pthread_mutex_unlock(&ctx->nacmlock);
		nacm_rele(old);
		return (c);
	}
	pthread_mutex_unlock(&ctx->nacmlock);
	return (c);	/* changed meanwhile: this one for this check */
}

void
cbl_ynacm_changed(cbl_ctx *ctx)
{

	if (ctx == NULL)
		return;
	pthread_mutex_lock(&ctx->nacmlock);
	ctx->nacmgen++;
	pthread_mutex_unlock(&ctx->nacmlock);
}

void
cbl_ynacm_counters(cbl_ctx *ctx, struct cbl_ynacm_counts *c)
{

	memset(c, 0, sizeof(*c));
	if (ctx == NULL)
		return;
	c->denied_operations = atomic_load(&ctx->nacm_denied_ops);
	c->denied_data_writes = atomic_load(&ctx->nacm_denied_writes);
	c->denied_notifications = atomic_load(&ctx->nacm_denied_notifs);
}

void
cbl_ynacm_free(cbl_ctx *ctx)
{

	nacm_rele(ctx->nacm);
	ctx->nacm = NULL;
}

/* The groups the user is in, by the rules' groups. */
static int
groups_of(const struct cbl_ynacm *c, const char *user, struct who_groups *g)
{

	g->n = 0;
	g->v = NULL;
	if (user == NULL || c->ngroups == 0)
		return (0);
	if ((g->v = calloc(c->ngroups, sizeof(*g->v))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < c->ngroups; i++)
		for (size_t j = 0; j < c->groups[i].nusers; j++)
			if (strcmp(c->groups[i].users[j], user) == 0) {
				g->v[g->n++] = c->groups[i].name;
				break;
			}
	return (0);
}

/* Whether a rule-list is the user's: one of its groups, or "*". */
static bool
list_applies(const struct nlist *l, const struct who_groups *g)
{

	for (size_t i = 0; i < l->ngroups; i++) {
		if (strcmp(l->groups[i], "*") == 0)
			return (true);
		for (size_t j = 0; j < g->n; j++)
			if (strcmp(l->groups[i], g->v[j]) == 0)
				return (true);
	}
	return (false);
}

static bool
rule_matches(const struct nrule *r, const struct target *t, unsigned op,
    const char *user)
{

	if ((r->ops & op) == 0 || (strcmp(r->module, "*") != 0 &&
	    (t->module == NULL || strcmp(r->module, t->module) != 0)))
		return (false);
	switch (r->type) {
	case RT_ANY:
		return (true);
	case RT_RPC:
		return (t->kind == T_RPC && (strcmp(r->name, "*") == 0 ||
		    strcmp(r->name, t->name) == 0));
	case RT_NOTIF:
		return (t->kind == T_NOTIF && (strcmp(r->name, "*") == 0 ||
		    strcmp(r->name, t->name) == 0));
	case RT_PATH:
		if (r->path == NULL)
			return (false);
		if (t->dn != NULL)
			return (cbl_dnacm_path_match(r->path, t->dn, user));
		return (t->sn != NULL && cbl_dnacm_path_match_schema(r->path,
		    t->sn));
	}
	return (false);
}

/* Section 3.4's verdict on op of t for user; true: permitted. */
static bool
allowed(const struct cbl_ynacm *c, const struct who_groups *g,
    const char *user, const struct target *t, unsigned op)
{

	if (!c->enable)
		return (true);
	if (c->broken)
		return (false);
	for (size_t i = 0; i < c->nlists; i++) {
		if (!list_applies(&c->lists[i], g))
			continue;
		for (size_t j = 0; j < c->lists[i].nrules; j++)
			if (rule_matches(&c->lists[i].rules[j], t, op, user))
				return (c->lists[i].rules[j].permit);
	}
	if ((t->deny & CBL_YNF_DENY_ALL) != 0)
		return (false);
	if ((op & A_WRITE) != 0 && (t->deny & CBL_YNF_DENY_WRITE) != 0)
		return (false);
	return ((op & A_READ) != 0 ? c->rd : (op & A_EXEC) != 0 ? c->ex :
	    c->wr);
}

/* The NACM flags on sn and the nodes above it. */
static unsigned
deny_of(const struct cbl_ynode *sn)
{
	unsigned f = 0;

	for (; sn != NULL; sn = sn->parent)
		f |= sn->flags & (CBL_YNF_DENY_WRITE | CBL_YNF_DENY_ALL);
	return (f);
}

/*
 * The user of a request: from the peer and what it said, by the
 * program's fn or the default.
 */
static int
user_default(const cbl_peer *p, const char *said, char *name, size_t len,
    bool *recovery, void *arg __unused)
{
	struct passwd pw, *res;
	char buf[1024];

	if (said != NULL)
		return (EACCES);
	name[0] = '\0';
	if (p->transport == CBL_TR_UNIX && p->has_cred) {
		if (p->uid == 0) {
			*recovery = true;
			return (0);
		}
		if (getpwuid_r(p->uid, &pw, buf, sizeof(buf), &res) == 0 &&
		    res != NULL)
			(void)strlcpy(name, res->pw_name, len);
		else
			(void)snprintf(name, len, "%u", (unsigned)p->uid);
		return (0);
	}
	if (p->subject != NULL)
		(void)strlcpy(name, p->subject, len);
	return (0);
}

int
cbl_ctx_set_user(cbl_ctx *ctx, cbl_user_f *fn, void *arg)
{

	if (ctx == NULL)
		return (EINVAL);
	pthread_mutex_lock(&ctx->mtx);
	ctx->user_fn = fn;
	ctx->user_arg = arg;
	pthread_mutex_unlock(&ctx->mtx);
	return (0);
}

int
cbl_msg_set_user(cbl_msg *msg, const char *user)
{
	struct cblink_user u = { .name = user };
	int error;

	if (msg == NULL || user == NULL || user[0] == '\0' ||
	    strlen(user) > 253 || msg->has_user)
		return (EINVAL);
	if ((error = cblink_user_put(msg, &u)) == 0)
		msg->has_user = true;
	return (error);
}

int
cbl_conn_set_user(cbl_conn *conn, const char *user)
{
	char *u = NULL;

	if (conn == NULL || (user != NULL && (user[0] == '\0' ||
	    strlen(user) > 253)))
		return (EINVAL);
	if (user != NULL && (u = strdup(user)) == NULL)
		return (ENOMEM);
	pthread_mutex_lock(&conn->mtx);
	free(conn->user);
	conn->user = u;
	pthread_mutex_unlock(&conn->mtx);
	return (0);
}

/* The user this thread's requests are made for, cbl_thread_set_user(). */
static _Thread_local char thread_user[254];

int
cbl_thread_set_user(const char *user)
{

	if (user != NULL && (user[0] == '\0' || strlen(user) > 253))
		return (EINVAL);
	(void)strlcpy(thread_user, user != NULL ? user : "",
	    sizeof(thread_user));
	return (0);
}

/* A request about to be sent on conn: the thread's user, or the
 * connection's, where it says none. */
void
cbl_conn_stamp(cbl_conn *conn, cbl_msg *msg)
{
	char *u = NULL;

	if (msg->has_user)
		return;
	if (thread_user[0] != '\0') {
		(void)cbl_msg_set_user(msg, thread_user);
		return;
	}
	pthread_mutex_lock(&conn->mtx);
	if (conn->user != NULL)
		u = strdup(conn->user);
	pthread_mutex_unlock(&conn->mtx);
	if (u != NULL)
		(void)cbl_msg_set_user(msg, u);
	free(u);
}

const char *
cbl_req_user(const cbl_req *req)
{

	return (req != NULL ? req->user : NULL);
}

int
cbl_req_who(cbl_req *req)
{
	const struct cbl_ynode *un = cbl_fw_node("user");
	struct cblink_user u;
	const void *raw;
	cbl_user_f *fn;
	cbl_yarena *a = NULL;
	char name[256], why[128];
	const char *said = NULL;
	void *arg;
	size_t len;
	bool recovery = false;
	int error = 0;

	if (un != NULL && cbl_msg_sid_raw(req->msg, un->sid, &raw, &len) == 0) {
		if ((a = cbl_yarena_new()) == NULL)
			return (ENOMEM);
		if (cblink_user_parse(req->msg, &u, a, CBL_YD_STRICT, why,
		    sizeof(why)) != 0) {
			cbl_yarena_free(a);
			(void)cbl_req_set_err(req, "a user said that is not one",
			    NULL, 0, -1);
			return (EINVAL);
		}
		said = u.name;
	}
	pthread_mutex_lock(&req->conn->ctx->mtx);
	fn = req->conn->ctx->user_fn != NULL ? req->conn->ctx->user_fn :
	    user_default;
	arg = req->conn->ctx->user_arg;
	pthread_mutex_unlock(&req->conn->ctx->mtx);
	name[0] = '\0';
	if ((error = fn(&req->conn->peer, said, name, sizeof(name), &recovery,
	    arg)) != 0) {
		(void)cbl_req_set_err(req, said != NULL ? "this peer may not "
		    "say whom it asks for" : "the peer is not let in", NULL, 0,
		    -1);
		cbl_yarena_free(a);
		return (error);
	}
	cbl_yarena_free(a);
	req->recovery = recovery;
	if (!recovery && (req->user = strdup(name)) == NULL)
		return (ENOMEM);
	return (0);
}

/* A check of t, op, for who: on the rules got for conn. */
static bool
check(cbl_ctx *ctx, cbl_conn *conn, const struct cbl_ywho *who,
    const struct target *t, unsigned op)
{
	struct cbl_ynacm *c;
	struct who_groups g;
	bool ok;

	if (who->recovery || (c = nacm_get(ctx, conn)) == NULL)
		return (true);
	if (groups_of(c, who->user, &g) != 0) {
		nacm_rele(c);
		return (false);
	}
	ok = allowed(c, &g, who->user, t, op);
	free(g.v);
	nacm_rele(c);
	return (ok);
}

int
cbl_ynacm_op(cbl_req *req, const char *module, const char *name, bool deny)
{
	struct cbl_ywho who = { req->user, req->recovery };
	struct target t = { .kind = T_RPC, .module = module, .name = name,
	    .deny = deny ? CBL_YNF_DENY_ALL : 0 };
	char text[160];

	if (check(req->conn->ctx, req->conn, &who, &t, A_EXEC))
		return (0);
	atomic_fetch_add(&req->conn->ctx->nacm_denied_ops, 1);
	(void)snprintf(text, sizeof(text), "access denied: %s:%s", module,
	    name);
	(void)cbl_req_set_err(req, text, NULL, 0, -1);
	return (EACCES);
}

int
cbl_ynacm_exec(cbl_req *req, const struct cbl_ynode *n)
{
	struct cbl_ywho who = { req->user, req->recovery };
	struct target t = { .kind = n->kind == CBL_YN_RPC ? T_RPC : T_DATA,
	    .module = n->module->name, .name = n->name, .sn = n,
	    .deny = deny_of(n) };

	if (check(req->conn->ctx, req->conn, &who, &t, A_EXEC))
		return (0);
	atomic_fetch_add(&req->conn->ctx->nacm_denied_ops, 1);
	return (cbl_ysay(req, EACCES, n->sid, "access-denied",
	    "access denied"));
}

bool
cbl_ynacm_notif(cbl_ctx *ctx, cbl_conn *conn, const struct cbl_ywho *who,
    const struct cbl_ynode *n)
{
	struct target t = { .kind = n->parent == NULL ? T_NOTIF : T_DATA,
	    .module = n->module->name, .name = n->name, .sn = n,
	    .deny = deny_of(n) };

	if (check(ctx, conn, who, &t, A_READ))
		return (true);
	atomic_fetch_add(&ctx->nacm_denied_notifs, 1);
	return (false);
}

/* Whether the first rule a read of any node meets permits it, so that
 * nothing is to be taken out. */
static bool
reads_all(const struct cbl_ynacm *c, const struct who_groups *g)
{

	if (!c->enable)
		return (true);
	if (c->broken)
		return (false);
	for (size_t i = 0; i < c->nlists; i++) {
		if (!list_applies(&c->lists[i], g))
			continue;
		for (size_t j = 0; j < c->lists[i].nrules; j++) {
			const struct nrule *r = &c->lists[i].rules[j];

			if ((r->ops & A_READ) == 0 || r->type == RT_RPC ||
			    r->type == RT_NOTIF)
				continue;
			return (r->permit && r->type == RT_ANY &&
			    strcmp(r->module, "*") == 0);
		}
	}
	return (false);
}

bool
cbl_ynacm_reads_all(cbl_ctx *ctx, cbl_conn *conn, const struct cbl_ywho *who)
{
	struct cbl_ynacm *c;
	struct who_groups g;
	bool all;

	if (who->recovery || (c = nacm_get(ctx, conn)) == NULL)
		return (true);
	if (groups_of(c, who->user, &g) != 0) {
		nacm_rele(c);
		return (false);
	}
	all = reads_all(c, &g);
	free(g.v);
	nacm_rele(c);
	return (all);
}

/* What under n may not be read taken out; a list entry whose key may not
 * be, whole. */
static void
prune(const struct cbl_ynacm *c, const struct who_groups *g,
    const char *user, cbl_dnode *n, unsigned *denied)
{
	cbl_dnode *k, *next;
	struct target t = { .kind = T_DATA };
	bool out;

	for (k = cbl_dnode_first(n); k != NULL; k = next) {
		next = cbl_dnode_next(k);
		t.sn = cbl_dnode_schema(k);
		t.dn = k;
		t.module = t.sn->module->name;
		t.name = t.sn->name;
		t.deny = deny_of(t.sn);
		out = !allowed(c, g, user, &t, A_READ);
		if (!out && t.sn->kind == CBL_YN_LIST)
			for (cbl_dnode *x = cbl_dnode_first(k); !out &&
			    x != NULL; x = cbl_dnode_next(x)) {
				if ((cbl_dnode_schema(x)->flags &
				    CBL_YNF_KEY) == 0)
					continue;
				t.sn = cbl_dnode_schema(x);
				t.dn = x;
				t.deny = deny_of(t.sn);
				out = !allowed(c, g, user, &t, A_READ);
			}
		if (out) {
			(void)cbl_dnode_remove(k);
			(*denied)++;
			continue;
		}
		prune(c, g, user, k, denied);
	}
}

int
cbl_ynacm_read(cbl_ctx *ctx, cbl_conn *conn, const struct cbl_ywho *who,
    cbl_dtree *t)
{
	struct cbl_ynacm *c;
	struct who_groups g;
	unsigned denied = 0;

	if (t == NULL || who->recovery || (c = nacm_get(ctx, conn)) == NULL)
		return (0);
	if (groups_of(c, who->user, &g) != 0) {
		nacm_rele(c);
		return (ENOMEM);
	}
	if (!reads_all(c, &g))
		prune(c, &g, who->user, cbl_dtree_root(t), &denied);
	free(g.v);
	nacm_rele(c);
	return (0);
}

/* A node of struct p of top-level node n, as a tree of schema s. */
static cbl_dtree *
tree_of(const struct cbl_yschema *s, const struct cbl_ynode *n,
    const void *p)
{
	struct cbl_ybuf b = { NULL, 0, 0 };
	cbl_dtree *t;
	char why[128];
	int error = 0;

	if ((t = cbl_dtree_new(s)) == NULL)
		return (NULL);
	if (p != NULL && cbl_ymember_present(n, p) &&
	    ((error = cbl_yencode_member(n, p, &b)) != 0 ||
	    (error = cbl_dnode_decode(cbl_dtree_root(t), n, b.p, b.len, 0,
	    why, sizeof(why), NULL)) != 0)) {
		cbl_ybuf_free(&b);
		cbl_dtree_free(t);
		return (NULL);
	}
	cbl_ybuf_free(&b);
	return (t);
}

/*
 * The first node of edit d (a diff, cbl_dtree_diff()) the user may not
 * change, or NULL: what is made, each node made with it; what is taken
 * away; a leaf whose value changes.
 */
static const cbl_dnode *
write_denied(const struct cbl_ynacm *c, const struct who_groups *g,
    const char *user, const cbl_dnode *n, int op)
{
	const struct cbl_ynode *sn;
	const cbl_dnode *bad;
	struct target t = { .kind = T_DATA };
	unsigned access;
	int o;

	for (const cbl_dnode *k = cbl_dnode_first(n); k != NULL;
	    k = cbl_dnode_next(k)) {
		o = cbl_dnode_op(k) != 0 ? cbl_dnode_op(k) : op;
		sn = cbl_dnode_schema(k);
		access = 0;
		if (o == CBL_DOP_CREATE || o == CBL_DOP_INSERT)
			access = A_CREATE;
		else if (o == CBL_DOP_DELETE || o == CBL_DOP_REMOVE)
			access = A_DELETE;
		else if ((o == CBL_DOP_MERGE || o == CBL_DOP_REPLACE ||
		    o == CBL_DOP_MOVE) && (sn->kind == CBL_YN_LEAF ||
		    sn->kind == CBL_YN_LEAFLIST || sn->kind ==
		    CBL_YN_ANYDATA || sn->kind == CBL_YN_ANYXML ||
		    o == CBL_DOP_MOVE))
			access = A_UPDATE;
		if (access != 0) {
			t.sn = sn;
			t.dn = k;
			t.module = sn->module->name;
			t.name = sn->name;
			t.deny = deny_of(sn);
			if (!allowed(c, g, user, &t, access))
				return (k);
		}
		/* What is taken away goes with all below it; what is made
		 * is each node made. */
		if (o == CBL_DOP_DELETE || o == CBL_DOP_REMOVE)
			continue;
		if ((bad = write_denied(c, g, user, k, o)) != NULL)
			return (bad);
	}
	return (NULL);
}

int
cbl_ynacm_write(cbl_req *req, const struct cbl_ynode *n, const void *before,
    const void *after)
{
	struct cbl_ywho who = { req->user, req->recovery };
	const struct cbl_yschema *s = n->module->schema;
	cbl_dtree *bt = NULL, *at = NULL, *d = NULL;
	const cbl_dnode *bad = NULL;
	struct cbl_ynacm *c;
	struct who_groups g;
	int error = 0;

	if (who.recovery || (c = nacm_get(req->conn->ctx, req->conn)) == NULL)
		return (0);
	if (!c->enable) {
		nacm_rele(c);
		return (0);
	}
	if (groups_of(c, who.user, &g) != 0) {
		nacm_rele(c);
		return (ENOMEM);
	}
	if (c->broken)
		error = EACCES;
	else if ((bt = tree_of(s, n, before)) == NULL ||
	    (at = tree_of(s, n, after)) == NULL ||
	    (d = cbl_dtree_diff(bt, at)) == NULL)
		error = errno != 0 ? errno : ENOMEM;
	else if ((bad = write_denied(c, &g, who.user, cbl_dtree_root(d),
	    CBL_DOP_MERGE)) != NULL)
		error = EACCES;
	free(g.v);
	nacm_rele(c);
	if (error == EACCES) {
		atomic_fetch_add(&req->conn->ctx->nacm_denied_writes, 1);
		error = cbl_ysay(req, EACCES, bad != NULL ?
		    cbl_dnode_schema(bad)->sid : n->sid, "access-denied",
		    "access denied");
	}
	cbl_dtree_free(d);
	cbl_dtree_free(at);
	cbl_dtree_free(bt);
	return (error);
}
