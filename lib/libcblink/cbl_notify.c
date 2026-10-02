/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Multicast groups and notifications (docs/WIRE-FORMAT.md section 9).
 *
 * Server side: each context maps group ids to member connections
 * (ctx->submtx).  A broadcast encodes the frame once and queues a
 * reference to it on every member.  A member whose send queue is full
 * misses the notification; the next one it does get carries CODE=ENOBUFS.
 *
 * Client side: subscriptions live on the connection (conn->mtx) and are
 * registered before the subscribe request goes out, so no notification
 * sent right after the server's ack is lost.
 *
 * Lock order: ctx->submtx before conn->mtx.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_impl.h"
#include "cbl_ctrl_gen.h"

static int
group_cmp(struct cbl_group *a, struct cbl_group *b)
{

	return ((a->gid > b->gid) - (a->gid < b->gid));
}

RB_GENERATE_STATIC(cbl_group_tree, cbl_group, link, group_cmp);

static struct cbl_group *
group_find(cbl_ctx *ctx, uint32_t gid, bool create)
{
	struct cbl_group key, *g;

	key.gid = gid;
	if ((g = RB_FIND(cbl_group_tree, &ctx->groups, &key)) != NULL ||
	    !create)
		return (g);
	if ((g = calloc(1, sizeof(*g))) == NULL)
		return (NULL);
	g->gid = gid;
	LIST_INIT(&g->members);
	RB_INSERT(cbl_group_tree, &ctx->groups, g);
	return (g);
}

static void
member_remove(cbl_ctx *ctx, struct cbl_member *m)
{
	struct cbl_group *g = m->g;

	LIST_REMOVE(m, glink);
	LIST_REMOVE(m, clink);
	free(m);
	if (LIST_EMPTY(&g->members)) {
		RB_REMOVE(cbl_group_tree, &ctx->groups, g);
		free(g);
	}
}

/* ctrl subscribe/unsubscribe on behalf of the peer of "req". */
int
cbl_sub_change(cbl_req *req, uint16_t family, uint32_t gid, bool subscribe)
{
	cbl_conn *conn = req->conn;
	cbl_ctx *ctx = conn->ctx;
	struct cbl_member *m;
	struct cbl_group *g;
	cbl_family *fam;
	uint32_t idx;
	int error = 0;

	if ((fam = cbl_family_lookup(ctx, family)) == NULL) {
		(void)cbl_req_set_err(req, "no such family", NULL, 0, -1);
		return (ENOENT);
	}
	if (gid < fam->group_base || fam->def->nmcgrps == 0 ||
	    gid - fam->group_base >= fam->def->nmcgrps) {
		cbl_family_rele(fam);
		(void)cbl_req_set_err(req, "no such group in this family",
		    NULL, 0, -1);
		return (ENOENT);
	}
	idx = gid - fam->group_base;
	if (subscribe && (fam->def->mcgrps[idx].flags & CBL_MCF_AUTH) != 0 &&
	    (conn->peer.flags & CBL_PEER_AUTHENTICATED) == 0) {
		cbl_family_rele(fam);
		(void)cbl_req_set_err(req, "authenticated peer required", NULL,
		    0, -1);
		return (EACCES);
	}
	cbl_family_rele(fam);

	pthread_mutex_lock(&ctx->submtx);
	LIST_FOREACH(m, &conn->memberships, clink)
		if (m->g->gid == gid)
			break;
	if (subscribe && m == NULL) {
		if ((g = group_find(ctx, gid, true)) == NULL ||
		    (m = calloc(1, sizeof(*m))) == NULL)
			error = ENOMEM;
		else {
			m->g = g;
			m->conn = conn;
			LIST_INSERT_HEAD(&g->members, m, glink);
			LIST_INSERT_HEAD(&conn->memberships, m, clink);
		}
	} else if (!subscribe && m != NULL)
		member_remove(ctx, m);
	pthread_mutex_unlock(&ctx->submtx);
	return (error);
}

/* A connection is closing: drop its memberships. */
void
cbl_notify_conn_closed(cbl_conn *conn)
{
	cbl_ctx *ctx = conn->ctx;
	struct cbl_member *m;

	pthread_mutex_lock(&ctx->submtx);
	while ((m = LIST_FIRST(&conn->memberships)) != NULL)
		member_remove(ctx, m);
	pthread_mutex_unlock(&ctx->submtx);
}

/* A family is gone: its groups have no members any more. */
void
cbl_notify_family_gone(cbl_ctx *ctx, const cbl_family *fam)
{
	struct cbl_member *m;
	struct cbl_group *g;

	pthread_mutex_lock(&ctx->submtx);
	for (uint32_t i = 0; i < fam->def->nmcgrps; i++) {
		if ((g = group_find(ctx, fam->group_base + i, false)) == NULL)
			continue;
		while ((m = LIST_FIRST(&g->members)) != NULL) {
			if (LIST_NEXT(m, glink) == NULL) {
				member_remove(ctx, m);	/* frees g */
				break;
			}
			member_remove(ctx, m);
		}
	}
	pthread_mutex_unlock(&ctx->submtx);
}

int
cbl_notify_msg_new(cbl_family *fam, uint16_t cmd, cbl_msg **msgp)
{
	cbl_msg *msg;
	int error;

	if (fam == NULL || msgp == NULL)
		return (EINVAL);
	if ((error = cbl_msg_new(fam->ctx, fam->id, cmd, CBL_F_NOTIFY,
	    &msg)) != 0)
		return (error);
	*msgp = msg;
	return (0);
}

/* A private copy of "msg" that also says notifications were missed. */
static cbl_msg *
copy_with_missed(cbl_conn *conn, cbl_msg *msg)
{
	const cbl_attr *body, *a;
	cbl_msg *rx = NULL, *copy;
	int error;

	unsigned char *buf;

	if ((buf = malloc(msg->len)) == NULL)
		return (NULL);
	memcpy(buf, msg->buf, msg->len);
	if (cbl_msg_from_frame(&conn->lim, buf, msg->len, &rx) != 0) {
		cbl_msg_free(rx);
		return (NULL);
	}
	if ((error = cbl_msg_alloc_empty(&conn->lim, &copy)) != 0) {
		cbl_msg_free(rx);
		return (NULL);
	}
	copy->hdr = msg->hdr;
	copy->hdr.length = 0;
	body = cbl_msg_body(rx);
	for (a = cbl_attr_first(body); a != NULL; a = cbl_attr_next(a))
		(void)cbl_put_attr(copy, cbl_attr_type(a), a);
	(void)cbl_msg_put_fw_uint(copy, CBL_FW_CODE, ENOBUFS);
	cbl_msg_free(rx);
	if (cbl_msg_encode(copy, NULL, NULL) != 0) {
		cbl_msg_free(copy);
		return (NULL);
	}
	return (copy);
}

/* Queue "msg" (holding one reference for us) on one connection. */
static int
deliver(cbl_conn *conn, cbl_msg *msg)
{
	cbl_msg *out = msg;
	int error;

	if (conn->ntf_missed && (out = copy_with_missed(conn, msg)) == NULL)
		out = msg;
	if (out == msg)
		(void)cbl_msg_ref(msg);
	error = cbl_conn_enqueue(conn, out);
	if (error == ENOBUFS) {
		conn->ntf_missed = true;
		conn->ntf_dropped++;
	} else if (error == 0 && out != msg)
		conn->ntf_missed = false;
	return (error);
}

static int
notify_prepare(cbl_family *fam, uint32_t group_idx, cbl_msg *msg)
{

	if (fam == NULL || msg == NULL || group_idx >= fam->def->nmcgrps)
		return (EINVAL);
	msg->hdr.family = fam->id;
	msg->hdr.flags = CBL_F_NOTIFY;
	msg->hdr.seq = 0;
	msg->hdr.stream = fam->group_base + group_idx;
	return (cbl_msg_encode(msg, NULL, NULL));
}

/* Broadcast to every subscriber of a group.  Thread-safe. */
int
cbl_notify(cbl_family *fam, uint32_t group_idx, cbl_msg *msg)
{
	struct cbl_member *m;
	struct cbl_group *g;
	cbl_ctx *ctx;
	int error;

	if ((error = notify_prepare(fam, group_idx, msg)) != 0) {
		cbl_msg_free(msg);
		return (error);
	}
	ctx = fam->ctx;
	pthread_mutex_lock(&ctx->submtx);
	if ((g = group_find(ctx, msg->hdr.stream, false)) != NULL)
		LIST_FOREACH(m, &g->members, glink)
			(void)deliver(m->conn, msg);
	pthread_mutex_unlock(&ctx->submtx);
	cbl_msg_free(msg);
	return (0);
}

/* Send a notification to one peer only. */
int
cbl_conn_notify(cbl_conn *conn, cbl_family *fam, uint32_t group_idx,
    cbl_msg *msg)
{
	int error;

	if (conn == NULL ||
	    (error = notify_prepare(fam, group_idx, msg)) != 0) {
		cbl_msg_free(msg);
		return (conn == NULL ? EINVAL : error);
	}
	pthread_mutex_lock(&conn->ctx->submtx);
	error = deliver(conn, msg);
	pthread_mutex_unlock(&conn->ctx->submtx);
	cbl_msg_free(msg);
	return (error);
}

/* newfamily/delfamily on the control family's "notify" group. */
void
cbl_ctrl_notify_family(cbl_ctx *ctx, cbl_family *fam, bool added)
{
	const struct cbl_family_def *def = fam->def;
	struct cbl_ctrl_op_info *ops = NULL;
	struct cbl_ctrl_group_info *grps = NULL;

	if (ctx->ctrl == NULL)
		return;
	if (!added) {
		struct cbl_ctrl_delfamily_ntf n = {
			.has_family_id = true, .family_id = fam->id,
			.family_name = def->name,
		};

		cbl_notify_family_gone(ctx, fam);
		(void)cbl_ctrl_delfamily_notify(ctx->ctrl, &n);
		return;
	}
	if ((def->nops > 0 &&
	    (ops = calloc(def->nops, sizeof(*ops))) == NULL) ||
	    (def->nmcgrps > 0 &&
	    (grps = calloc(def->nmcgrps, sizeof(*grps))) == NULL)) {
		free(ops);
		return;
	}
	for (uint32_t i = 0; i < def->nops; i++) {
		ops[i].has_cmd = true;
		ops[i].cmd = def->ops[i].cmd;
		ops[i].name = def->ops[i].name;
		ops[i].has_flags = true;
		ops[i].flags = def->ops[i].flags;
	}
	for (uint32_t i = 0; i < def->nmcgrps; i++) {
		grps[i].has_id = true;
		grps[i].id = fam->group_base + i;
		grps[i].name = def->mcgrps[i].name;
		grps[i].has_flags = true;
		grps[i].flags = def->mcgrps[i].flags;
	}
	struct cbl_ctrl_newfamily_ntf n = {
		.has_family_id = true, .family_id = fam->id,
		.family_name = def->name,
		.has_version = true, .version = def->version,
	};
	n.ops.n = def->nops;
	n.ops.v = ops;
	n.mcast_groups.n = def->nmcgrps;
	n.mcast_groups.v = grps;
	(void)cbl_ctrl_newfamily_notify(ctx->ctrl, &n);
	free(ops);
	free(grps);
}

/*
 * Client side.
 */
/* A notification arrived (I/O thread). */
void
cbl_notify_rx(cbl_conn *conn, cbl_msg *msg)
{
	struct cbl_sub *s, **hit = NULL;
	size_t n = 0, cap = 0;

	/* Pin the matching subscriptions, then call them unlocked. */
	pthread_mutex_lock(&conn->mtx);
	LIST_FOREACH(s, &conn->subs, link) {
		if (s->dead || s->family != msg->hdr.family ||
		    s->group != msg->hdr.stream)
			continue;
		if (n == cap) {
			struct cbl_sub **nh;

			cap = cap == 0 ? 4 : cap * 2;
			if ((nh = reallocarray(hit, cap, sizeof(*hit))) == NULL)
				break;
			hit = nh;
		}
		s->refs++;
		hit[n++] = s;
	}
	pthread_mutex_unlock(&conn->mtx);
	for (size_t i = 0; i < n; i++)
		hit[i]->cb(conn, msg, hit[i]->arg);
	pthread_mutex_lock(&conn->mtx);
	for (size_t i = 0; i < n; i++)
		if (--hit[i]->refs == 0 && hit[i]->dead && !hit[i]->waiter)
			free(hit[i]);
	pthread_cond_broadcast(&conn->cv);
	pthread_mutex_unlock(&conn->mtx);
	free(hit);
	cbl_msg_free(msg);
}

int
cbl_subscribe_id(cbl_conn *conn, uint16_t family, uint32_t group,
    cbl_notify_f *cb, void *arg, cbl_sub **subp)
{
	struct cbl_ctrl_subscribe_req rq = {
		.has_family_id = true, .family_id = family,
		.has_group_id = true, .group_id = group,
	};
	struct cbl_ctrl_client cl;
	struct cbl_sub *s;
	int error;

	if (conn == NULL || cb == NULL || subp == NULL || group == 0)
		return (EINVAL);
	if ((s = calloc(1, sizeof(*s))) == NULL)
		return (ENOMEM);
	s->conn = conn;
	s->family = family;
	s->group = group;
	s->cb = cb;
	s->arg = arg;
	/* Listen before asking, so nothing sent after the ack is lost. */
	pthread_mutex_lock(&conn->mtx);
	LIST_INSERT_HEAD(&conn->subs, s, link);
	pthread_mutex_unlock(&conn->mtx);
	(void)cbl_ctrl_client_init(&cl, conn);
	error = cbl_ctrl_subscribe(&cl, &rq);
	cbl_ctrl_client_fini(&cl);
	if (error != 0) {
		pthread_mutex_lock(&conn->mtx);
		LIST_REMOVE(s, link);
		while (s->refs > 0)
			pthread_cond_wait(&conn->cv, &conn->mtx);
		pthread_mutex_unlock(&conn->mtx);
		free(s);
		return (error);
	}
	*subp = s;
	return (0);
}

int
cbl_subscribe(cbl_conn *conn, const char *family, const char *group,
    cbl_notify_f *cb, void *arg, cbl_sub **subp)
{
	cbl_family_info *info;
	uint32_t gid;
	uint16_t fid;
	int error;

	if (conn == NULL || family == NULL || group == NULL)
		return (EINVAL);
	if ((error = cbl_resolve(conn, family, &info)) != 0)
		return (error);
	fid = cbl_family_info_id(info);
	error = cbl_family_info_group(info, group, &gid);
	cbl_family_info_free(info);
	if (error != 0)
		return (error);
	return (cbl_subscribe_id(conn, fid, gid, cb, arg, subp));
}

static void
unsub_done(cbl_conn *conn __unused, cbl_msg *reply __unused,
    bool final __unused, int error __unused, void *arg __unused)
{
}

/*
 * Stop a subscription.  Never blocks on the network; when called off the
 * I/O thread it waits for a running callback of this subscription, so
 * the caller may free the callback's argument afterwards.
 */
int
cbl_unsubscribe(cbl_sub *s)
{
	cbl_conn *conn;
	cbl_msg *msg;
	bool free_now;

	if (s == NULL)
		return (EINVAL);
	conn = s->conn;
	pthread_mutex_lock(&conn->mtx);
	LIST_REMOVE(s, link);
	s->dead = true;
	if (!cbl_conn_io_thread(conn)) {
		s->waiter = true;
		while (s->refs > 0)
			pthread_cond_wait(&conn->cv, &conn->mtx);
	}
	/* Otherwise a callback still running frees it when it returns. */
	free_now = s->refs == 0;
	pthread_mutex_unlock(&conn->mtx);
	if (conn->state == CBL_CS_OPEN && cbl_msg_new(conn->ctx,
	    CBL_CTRL_FAMILY, CBL_CTRL_CMD_UNSUBSCRIBE, 0, &msg) == 0) {
		(void)cbl_ctrl_put_family_id(msg, s->family);
		(void)cbl_ctrl_put_group_id(msg, s->group);
		(void)cbl_request_async(conn, msg, unsub_done, NULL);
	}
	if (free_now)
		free(s);
	return (0);
}

void *
cbl_sub_arg(const cbl_sub *s)
{

	return (s != NULL ? s->arg : NULL);
}

/*
 * The connection object is being freed: release subscriptions the
 * application did not cancel.  (cbl_unsubscribe() must come first.)
 */
void
cbl_sub_free_all(cbl_conn *conn)
{
	struct cbl_sub *s;

	while ((s = LIST_FIRST(&conn->subs)) != NULL) {
		LIST_REMOVE(s, link);
		free(s);
	}
}

/*
 * Subscriptions without waiting, for a client on a loop: "done" runs on
 * the I/O thread with the subscription, or an error.
 */
struct sub_call {
	struct cbl_ctrl_client	 cl;
	struct cbl_sub		*s;
	cbl_subscribed_f	*done;
	void			*arg;
	cbl_notify_f		*cb;	/* by name: once resolved */
	void			*cb_arg;
	char			 group[CBL_FAMILY_NAME_MAX + 1];
};

static void
sub_done(struct cbl_ctrl_client *cl, int error, void *arg)
{
	struct sub_call *sc = arg;
	cbl_conn *conn = cl->conn;
	struct cbl_sub *s = sc->s;

	if (error != 0) {
		/* On the I/O thread: no notification runs for it now. */
		pthread_mutex_lock(&conn->mtx);
		LIST_REMOVE(s, link);
		pthread_mutex_unlock(&conn->mtx);
		free(s);
		s = NULL;
	}
	sc->done(conn, error, s, sc->arg);
	cbl_ctrl_client_fini(&sc->cl);
	free(sc);
}

static int
sub_start(struct sub_call *sc, cbl_conn *conn, uint16_t family,
    uint32_t group, cbl_notify_f *cb, void *arg)
{
	struct cbl_ctrl_subscribe_req rq = {
		.has_family_id = true, .family_id = family,
		.has_group_id = true, .group_id = group,
	};
	struct cbl_sub *s;
	int error;

	if ((s = calloc(1, sizeof(*s))) == NULL)
		return (ENOMEM);
	s->conn = conn;
	s->family = family;
	s->group = group;
	s->cb = cb;
	s->arg = arg;
	/* Listen before asking, so nothing sent after the ack is lost. */
	pthread_mutex_lock(&conn->mtx);
	LIST_INSERT_HEAD(&conn->subs, s, link);
	pthread_mutex_unlock(&conn->mtx);
	sc->s = s;
	(void)cbl_ctrl_client_init(&sc->cl, conn);
	if ((error = cbl_ctrl_subscribe_async(&sc->cl, &rq, sub_done,
	    sc)) != 0) {
		pthread_mutex_lock(&conn->mtx);
		LIST_REMOVE(s, link);
		pthread_mutex_unlock(&conn->mtx);
		free(s);
		cbl_ctrl_client_fini(&sc->cl);
	}
	return (error);
}

int
cbl_subscribe_id_async(cbl_conn *conn, uint16_t family, uint32_t group,
    cbl_notify_f *cb, void *arg, cbl_subscribed_f *done, void *done_arg)
{
	struct sub_call *sc;
	int error;

	if (conn == NULL || cb == NULL || done == NULL || group == 0)
		return (EINVAL);
	if ((sc = calloc(1, sizeof(*sc))) == NULL)
		return (ENOMEM);
	sc->done = done;
	sc->arg = done_arg;
	if ((error = sub_start(sc, conn, family, group, cb, arg)) != 0)
		free(sc);
	return (error);
}

static void
sub_resolved(cbl_conn *conn, int error, cbl_family_info *info, void *arg)
{
	struct sub_call *sc = arg;
	uint32_t gid;

	if (error == 0)
		error = cbl_family_info_group(info, sc->group, &gid);
	if (error == 0)
		error = sub_start(sc, conn, cbl_family_info_id(info), gid,
		    sc->cb, sc->cb_arg);
	cbl_family_info_free(info);
	if (error != 0) {
		sc->done(conn, error, NULL, sc->arg);
		free(sc);
	}
}

int
cbl_subscribe_async(cbl_conn *conn, const char *family, const char *group,
    cbl_notify_f *cb, void *arg, cbl_subscribed_f *done, void *done_arg)
{
	struct sub_call *sc;
	int error;

	if (conn == NULL || family == NULL || group == NULL || cb == NULL ||
	    done == NULL || strlen(group) >= sizeof(sc->group))
		return (EINVAL);
	if ((sc = calloc(1, sizeof(*sc))) == NULL)
		return (ENOMEM);
	sc->done = done;
	sc->arg = done_arg;
	sc->cb = cb;
	sc->cb_arg = arg;
	strlcpy(sc->group, group, sizeof(sc->group));
	if ((error = cbl_resolve_async(conn, family, sub_resolved, sc)) != 0)
		free(sc);
	return (error);
}
