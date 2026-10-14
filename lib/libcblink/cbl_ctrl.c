/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The built-in control family (family 0, "ctrl"), docs/WIRE-FORMAT.md
 * section 7.2: the rpcs and notifications of the YANG module cblink-ctrl
 * (share/yang/cblink-ctrl@2026-10-13.yang), whose structs and tables
 * cblink-gen makes (cbl_yctrl.h, cbl_yctrl_schema.c).  A command's
 * request is {SID(rpc): input}, its reply {SID(rpc): output}; hello is
 * the cblink module's hello structure both ways.  This file holds the
 * handlers, the family's definition, and the client calls built on it.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_impl.h"
#include "cbl_schema.h"
#include "cbl_yctrl.h"
#include "cbl_ymod.h"

#define	CBL_IMPL_NAME	"libcblink/0.1.0"
#define	CBL_PEER_MIN_FRAME	4096

/* The module's rpc or notification named name. */
static const struct cbl_ynode *
ctrl_node(const char *name)
{
	const struct cbl_ymodule *m = cbl_yctrl_schema.mod[0];

	for (uint32_t i = 0; i < m->ntop; i++)
		if (strcmp(m->top[i]->name, name) == 0)
			return (m->top[i]);
	return (NULL);
}

/* An rpc's input or output. */
static const struct cbl_ynode *
ctrl_io(const char *rpc, int kind)
{
	const struct cbl_ynode *n = ctrl_node(rpc);

	for (uint32_t i = 0; n != NULL && i < n->nchild; i++)
		if (n->child[i]->kind == kind)
			return (n->child[i]);
	return (NULL);
}

/* Flags as bits: position p in byte p / 8, from the low bit; no zero
 * bytes at the end (RFC 9254 section 6.7). */
static struct cbl_bytes
flags_bits(uint32_t f, uint8_t *buf)
{
	struct cbl_bytes b = { buf, 0 };

	for (size_t i = 0; i < 4; i++) {
		buf[i] = (uint8_t)(f >> (8 * i));
		if (buf[i] != 0)
			b.len = i + 1;
	}
	return (b);
}

static uint32_t
bits_flags(const struct cbl_bytes *b)
{
	uint32_t f = 0;

	for (size_t i = 0; i < b->len && i < 4; i++)
		f |= (uint32_t)((const uint8_t *)b->p)[i] << (8 * i);
	return (f);
}

/*
 * A family as the grouping family-info has it, in get-family's output
 * or in family-added: the same members, two types.  Its arrays are a's.
 */
#define	DEFINE_FILL(fname, otype, optype, grptype)			\
static int								\
fname(otype *o, const cbl_family *fam, cbl_yarena *a)			\
{									\
	const struct cbl_family_def *def = fam->def;			\
	optype *ops = NULL;						\
	grptype *grps = NULL;						\
	uint8_t *bits;							\
									\
	if ((def->nops > 0 && (ops = cbl_yarena_alloc(a,		\
	    def->nops * sizeof(*ops))) == NULL) ||			\
	    (def->nmcgrps > 0 && (grps = cbl_yarena_alloc(a,		\
	    def->nmcgrps * sizeof(*grps))) == NULL) ||			\
	    (bits = cbl_yarena_alloc(a, 4 * (def->nops +		\
	    def->nmcgrps))) == NULL)					\
		return (ENOMEM);					\
	for (uint32_t i = 0; i < def->nops; i++) {			\
		ops[i].cmd = def->ops[i].cmd;				\
		ops[i].name = def->ops[i].name;				\
		ops[i].flags = flags_bits(def->ops[i].flags, bits);	\
		bits += 4;						\
	}								\
	for (uint32_t i = 0; i < def->nmcgrps; i++) {			\
		grps[i].id = fam->group_base + i;			\
		grps[i].name = def->mcgrps[i].name;			\
		grps[i].flags = flags_bits(def->mcgrps[i].flags, bits);	\
		bits += 4;						\
	}								\
	o->has_id = true;						\
	o->id = fam->id;						\
	o->name = def->name;						\
	o->has_version = true;						\
	o->version = def->version;					\
	o->op.n = def->nops;						\
	o->op.v = ops;							\
	o->group.n = def->nmcgrps;					\
	o->group.v = grps;						\
	return (0);							\
}

DEFINE_FILL(fill_info, struct cblink_ctrl_get_family_output,
    struct cblink_ctrl_get_family_output_op,
    struct cblink_ctrl_get_family_output_group)
DEFINE_FILL(fill_added, struct cblink_ctrl_family_added,
    struct cblink_ctrl_family_added_op,
    struct cblink_ctrl_family_added_group)

/*
 * Server side.
 */

/* A command's input: none sent, an empty one. */
static int
ctrl_input(cbl_req *req, const cbl_msg *msg, const char *rpc, void *in,
    cbl_yarena *a)
{
	char why[128];
	int error;

	error = cbl_msg_ydecode(msg, ctrl_io(rpc, CBL_YN_INPUT), in, a,
	    CBL_YD_STRICT, why, sizeof(why));
	if (error == ENOENT)
		return (0);
	if (error != 0) {
		(void)cbl_req_set_err(req, why, NULL, 0, -1);
		req->err_ysid = ctrl_node(rpc)->sid;
		req->err_ytag = "bad-element";
	}
	return (error);
}

/* A reply of rpc's output; a dump's item when the request is a dump. */
static int
ctrl_reply(cbl_req *req, const char *rpc, const void *out)
{
	const struct cbl_ynode *o = ctrl_io(rpc, CBL_YN_OUTPUT);
	cbl_msg *msg;
	int error;

	if ((error = cbl_req_reply_new(req, 0, &msg)) != 0)
		return (error);
	error = o->nchild == 0 ? cbl_msg_put_ynull(msg, ctrl_node(rpc)->sid) :
	    cbl_msg_put_ynode(msg, o, out);
	if (error != 0) {
		cbl_msg_free(msg);
		return (error);
	}
	return (cbl_req_send(req, msg));
}

static int
getfamily_reply(cbl_req *req, cbl_family *fam)
{
	struct cblink_ctrl_get_family_output o = { 0 };
	cbl_yarena *a;
	int error;

	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if ((error = fill_info(&o, fam, a)) == 0)
		error = ctrl_reply(req, "get-family", &o);
	cbl_yarena_free(a);
	return (error);
}

static int
getfamily_doit(cbl_req *req, const cbl_msg *msg, void *arg __unused)
{
	struct cblink_ctrl_get_family_input in = { 0 };
	cbl_family *fam;
	cbl_yarena *a;
	int error;

	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if ((error = ctrl_input(req, msg, "get-family", &in, a)) != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	if (in.name != NULL)
		fam = cbl_family_lookup_name(req->conn->ctx, in.name);
	else if (in.has_id)
		fam = cbl_family_lookup(req->conn->ctx, in.id);
	else {
		cbl_yarena_free(a);
		(void)cbl_req_set_err(req, "id or name required", NULL, 0, -1);
		req->err_ysid = ctrl_node("get-family")->sid;
		req->err_ytag = "missing-element";
		return (EINVAL);
	}
	cbl_yarena_free(a);
	if (fam == NULL) {
		(void)cbl_req_set_err(req, "no such family", NULL, 0, -1);
		return (ENOENT);
	}
	error = getfamily_reply(req, fam);
	cbl_family_rele(fam);
	return (error);
}

/* One family per call; pos[0] is the next id to look at. */
static int
getfamily_dumpit(cbl_req *req, const cbl_msg *msg __unused,
    struct cbl_dump_state *st, void *arg __unused)
{
	cbl_family *fam;
	int error;

	if ((fam = cbl_family_next(req->conn->ctx, (uint32_t)st->pos[0])) ==
	    NULL)
		return (0);
	st->pos[0] = (uint64_t)fam->id + 1;
	error = getfamily_reply(req, fam);
	cbl_family_rele(fam);
	return (error != 0 ? error : EAGAIN);
}

/* subscribe's or unsubscribe's: the family and group, both needed. */
static int
sub_change(cbl_req *req, const char *rpc, bool has_f, uint16_t family,
    bool has_g, uint32_t group, bool subscribe)
{

	if (!has_f || !has_g) {
		(void)cbl_req_set_err(req, "family-id and group-id required",
		    NULL, 0, -1);
		req->err_ysid = ctrl_node(rpc)->sid;
		req->err_ytag = "missing-element";
		return (EINVAL);
	}
	return (cbl_sub_change(req, family, group, subscribe));
}

static int
subscribe_doit(cbl_req *req, const cbl_msg *msg, void *arg __unused)
{
	struct cblink_ctrl_subscribe_input in = { 0 };
	cbl_yarena *a;
	int error;

	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	error = ctrl_input(req, msg, "subscribe", &in, a);
	cbl_yarena_free(a);
	if (error != 0)
		return (error);
	return (sub_change(req, "subscribe", in.has_family_id, in.family_id,
	    in.has_group_id, in.group_id, true));
}

static int
unsubscribe_doit(cbl_req *req, const cbl_msg *msg, void *arg __unused)
{
	struct cblink_ctrl_unsubscribe_input in = { 0 };
	cbl_yarena *a;
	int error;

	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	error = ctrl_input(req, msg, "unsubscribe", &in, a);
	cbl_yarena_free(a);
	if (error != 0)
		return (error);
	return (sub_change(req, "unsubscribe", in.has_family_id, in.family_id,
	    in.has_group_id, in.group_id, false));
}

static int
ping_doit(cbl_req *req, const cbl_msg *msg, void *arg __unused)
{
	struct cblink_ctrl_ping_input in = { 0 };
	struct cblink_ctrl_ping_output out = { 0 };
	cbl_yarena *a;
	int error;

	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if ((error = ctrl_input(req, msg, "ping", &in, a)) == 0) {
		out.cookie = in.cookie;
		error = ctrl_reply(req, "ping", &out);
	}
	cbl_yarena_free(a);
	return (error);
}

/*
 * The largest frame the peer said it takes (ctrl hello), never below the
 * smallest max_frame there is (WIRE-FORMAT.md section 11): a peer cannot
 * shrink our frames to nothing.  0 keeps what we had.
 */
static void
set_peer_max_frame(cbl_conn *conn, uint64_t v)
{

	if (v == 0)
		return;
	pthread_mutex_lock(&conn->mtx);
	conn->peer_max_frame = v < CBL_PEER_MIN_FRAME ? CBL_PEER_MIN_FRAME : v;
	pthread_mutex_unlock(&conn->mtx);
}

/* Our limits and name, as the hello structure says them. */
static void
our_hello(const cbl_conn *conn, struct cblink_hello *h,
    struct cblink_hello_limits *l)
{
	const struct cbl_limits *lim = &conn->lim;

	memset(l, 0, sizeof(*l));
	l->has_max_frame = true;
	l->max_frame = lim->v[CBL_LIM_MAX_FRAME];
	l->has_max_depth = true;
	l->max_depth = (uint32_t)lim->v[CBL_LIM_MAX_DEPTH];
	l->has_max_attrs = true;
	l->max_attrs = (uint32_t)lim->v[CBL_LIM_MAX_ATTRS];
	l->has_max_streams = true;
	l->max_streams = (uint32_t)lim->v[CBL_LIM_MAX_STREAMS];
	l->has_stream_window = true;
	l->stream_window = (uint32_t)lim->v[CBL_LIM_STREAM_WINDOW];
	memset(h, 0, sizeof(*h));
	h->limits = l;
	h->implementation = CBL_IMPL_NAME;
}

static int
hello_doit(cbl_req *req, const cbl_msg *msg, void *arg __unused)
{
	struct cblink_hello h, peer = { 0 };
	struct cblink_hello_limits l;
	cbl_yarena *a;
	cbl_msg *reply;
	int error;

	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	/* Remember what the peer can take. */
	error = cbl_msg_ydecode(msg, cbl_fw_node("hello"), &peer, a,
	    CBL_YD_STRICT, NULL, 0);
	if (error == 0 && peer.limits != NULL && peer.limits->has_max_frame)
		set_peer_max_frame(req->conn, peer.limits->max_frame);
	cbl_yarena_free(a);
	if (error != 0 && error != ENOENT)
		return (error);
	our_hello(req->conn, &h, &l);
	if ((error = cbl_req_reply_new(req, 0, &reply)) != 0)
		return (error);
	if ((error = cbl_msg_put_ynode(reply, cbl_fw_node("hello"),
	    &h)) != 0) {
		cbl_msg_free(reply);
		return (error);
	}
	return (cbl_req_send(req, reply));
}

static const struct cbl_op ctrl_ops[] = {
	{ .cmd = CBL_CTRL_CMD_GETFAMILY, .flags = CBL_OPF_DO | CBL_OPF_DUMP,
	    .name = "get-family", .doit = getfamily_doit,
	    .dumpit = getfamily_dumpit },
	{ .cmd = CBL_CTRL_CMD_SUBSCRIBE, .flags = CBL_OPF_DO,
	    .name = "subscribe", .doit = subscribe_doit },
	{ .cmd = CBL_CTRL_CMD_UNSUBSCRIBE, .flags = CBL_OPF_DO,
	    .name = "unsubscribe", .doit = unsubscribe_doit },
	{ .cmd = CBL_CTRL_CMD_PING, .flags = CBL_OPF_DO, .name = "ping",
	    .doit = ping_doit },
	{ .cmd = CBL_CTRL_CMD_HELLO, .flags = CBL_OPF_DO, .name = "hello",
	    .doit = hello_doit },
};

static const struct cbl_mcgrp ctrl_groups[] = {
	{ "notify", 0 },
};

static const struct cbl_family_def ctrl_def = {
	.abi = CBL_FAMILY_ABI,
	.name = "ctrl",
	.version = 2,
	.ops = ctrl_ops,
	.nops = sizeof(ctrl_ops) / sizeof(ctrl_ops[0]),
	.mcgrps = ctrl_groups,
	.nmcgrps = sizeof(ctrl_groups) / sizeof(ctrl_groups[0]),
};

int
cbl_ctrl_register(cbl_ctx *ctx)
{

	return (cbl_ctx_add_builtin(ctx, &ctrl_def, NULL));
}

/* family-added or family-removed, to the "notify" group. */
void
cbl_ctrl_notify_family(cbl_ctx *ctx, cbl_family *fam, bool added)
{
	struct cblink_ctrl_family_removed rm = { 0 };
	struct cblink_ctrl_family_added ad = { 0 };
	cbl_yarena *a;

	if (ctx->ctrl == NULL)
		return;
	if (!added) {
		cbl_notify_family_gone(ctx, fam);
		rm.has_id = true;
		rm.id = fam->id;
		rm.name = fam->def->name;
		(void)cbl_ynotify_fam(ctx->ctrl, 0, CBL_CTRL_CMD_DELFAMILY,
		    ctrl_node("family-removed"), &rm);
		return;
	}
	if ((a = cbl_yarena_new()) == NULL)
		return;
	if (fill_added(&ad, fam, a) == 0)
		(void)cbl_ynotify_fam(ctx->ctrl, 0, CBL_CTRL_CMD_NEWFAMILY,
		    ctrl_node("family-added"), &ad);
	cbl_yarena_free(a);
}

/*
 * Client side.
 */

/* A request of the control family: cmd, its rpc's input in. */
int
cbl_ctrl_msg(cbl_conn *conn, uint16_t cmd, const char *rpc, const void *in,
    uint32_t flags, cbl_msg **msgp)
{
	cbl_msg *msg;
	int error;

	if ((error = cbl_msg_new(conn->ctx, CBL_CTRL_FAMILY, cmd, flags,
	    &msg)) != 0)
		return (error);
	if (in != NULL && (error = cbl_msg_put_ynode(msg,
	    ctrl_io(rpc, CBL_YN_INPUT), in)) != 0) {
		cbl_msg_free(msg);
		return (error);
	}
	*msgp = msg;
	return (0);
}

/* subscribe or unsubscribe's request. */
int
cbl_ctrl_sub_msg(cbl_conn *conn, bool subscribe, uint16_t family,
    uint32_t group, cbl_msg **msgp)
{
	struct cblink_ctrl_subscribe_input in = {
		.has_family_id = true, .family_id = family,
		.has_group_id = true, .group_id = group,
	};
	struct cblink_ctrl_unsubscribe_input out = {
		.has_family_id = true, .family_id = family,
		.has_group_id = true, .group_id = group,
	};

	if (subscribe)
		return (cbl_ctrl_msg(conn, CBL_CTRL_CMD_SUBSCRIBE, "subscribe",
		    &in, 0, msgp));
	return (cbl_ctrl_msg(conn, CBL_CTRL_CMD_UNSUBSCRIBE, "unsubscribe",
	    &out, 0, msgp));
}

struct cbl_family_info {
	uint16_t	 id;
	uint32_t	 version;
	char		 name[CBL_FAMILY_NAME_MAX + 1];
	size_t		 nops;
	struct {
		uint16_t	 cmd;
		uint32_t	 flags;
	}		*ops;
	size_t		 ngroups;
	struct {
		uint32_t	 id;
		char		 name[CBL_FAMILY_NAME_MAX + 1];
	}		*groups;
};

/* A get-family reply as a cbl_family_info. */
static int
info_from_reply(const cbl_msg *rsp, cbl_family_info **infop)
{
	struct cblink_ctrl_get_family_output o = { 0 };
	cbl_family_info *info = NULL;
	cbl_yarena *a;
	int error;

	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if (cbl_msg_ydecode(rsp, ctrl_io("get-family", CBL_YN_OUTPUT), &o, a,
	    CBL_YD_STRICT, NULL, 0) != 0 || o.name == NULL || !o.has_id) {
		error = EPROTO;
		goto out;
	}
	error = ENOMEM;
	if ((info = calloc(1, sizeof(*info))) == NULL ||
	    (o.op.n > 0 && (info->ops = calloc(o.op.n,
	    sizeof(*info->ops))) == NULL) ||
	    (o.group.n > 0 && (info->groups = calloc(o.group.n,
	    sizeof(*info->groups))) == NULL))
		goto out;
	info->id = o.id;
	info->version = o.version;
	strlcpy(info->name, o.name, sizeof(info->name));
	for (size_t i = 0; i < o.op.n; i++) {
		info->ops[i].cmd = o.op.v[i].cmd;
		info->ops[i].flags = bits_flags(&o.op.v[i].flags);
	}
	info->nops = o.op.n;
	for (size_t i = 0; i < o.group.n; i++) {
		info->groups[i].id = o.group.v[i].id;
		if (o.group.v[i].name != NULL)
			strlcpy(info->groups[i].name, o.group.v[i].name,
			    sizeof(info->groups[i].name));
	}
	info->ngroups = o.group.n;
	*infop = info;
	info = NULL;
	error = 0;
out:
	cbl_family_info_free(info);
	cbl_yarena_free(a);
	return (error);
}

static int
resolve_msg(cbl_conn *conn, const char *family, cbl_msg **msgp)
{
	struct cblink_ctrl_get_family_input in = { .name = family };

	return (cbl_ctrl_msg(conn, CBL_CTRL_CMD_GETFAMILY, "get-family", &in,
	    0, msgp));
}

int
cbl_resolve(cbl_conn *conn, const char *family, cbl_family_info **infop)
{
	cbl_msg *msg, *rsp;
	int error;

	if (conn == NULL || family == NULL || infop == NULL)
		return (EINVAL);
	if ((error = resolve_msg(conn, family, &msg)) != 0)
		return (error);
	if ((error = cbl_request(conn, msg, &rsp, -1)) == 0)
		error = info_from_reply(rsp, infop);
	cbl_msg_free(rsp);
	return (error);
}

/* cbl_resolve() without waiting: for a client on a loop. */
struct resolve_call {
	cbl_resolve_f	*cb;
	void		*arg;
	cbl_msg		*rsp;
};

static void
resolve_done(cbl_conn *conn, cbl_msg *m, bool final, int error, void *arg)
{
	struct resolve_call *rc = arg;
	cbl_family_info *info = NULL;

	if (!final) {
		if (rc->rsp == NULL && m != NULL && cbl_msg_ref(m) == 0)
			rc->rsp = m;
		return;
	}
	if (error == 0)
		error = rc->rsp != NULL ? info_from_reply(rc->rsp, &info) :
		    EPROTO;
	cbl_msg_free(rc->rsp);
	rc->cb(conn, error, info, rc->arg);
	free(rc);
}

int
cbl_resolve_async(cbl_conn *conn, const char *family, cbl_resolve_f *cb,
    void *arg)
{
	struct resolve_call *rc;
	cbl_msg *msg;
	int error;

	if (conn == NULL || family == NULL || cb == NULL)
		return (EINVAL);
	if ((rc = calloc(1, sizeof(*rc))) == NULL)
		return (ENOMEM);
	rc->cb = cb;
	rc->arg = arg;
	if ((error = resolve_msg(conn, family, &msg)) != 0 ||
	    (error = cbl_request_async(conn, msg, resolve_done, rc)) != 0)
		free(rc);
	return (error);
}

uint16_t
cbl_family_info_id(const cbl_family_info *info)
{

	return (info != NULL ? info->id : 0);
}

uint32_t
cbl_family_info_version(const cbl_family_info *info)
{

	return (info != NULL ? info->version : 0);
}

const char *
cbl_family_info_name(const cbl_family_info *info)
{

	return (info != NULL ? info->name : NULL);
}

size_t
cbl_family_info_nops(const cbl_family_info *info)
{

	return (info != NULL ? info->nops : 0);
}

int
cbl_family_info_group(const cbl_family_info *info, const char *name,
    uint32_t *idp)
{

	if (info == NULL || name == NULL)
		return (EINVAL);
	for (size_t i = 0; i < info->ngroups; i++) {
		if (strcmp(info->groups[i].name, name) == 0) {
			if (idp != NULL)
				*idp = info->groups[i].id;
			return (0);
		}
	}
	return (ENOENT);
}

int
cbl_family_info_op(const cbl_family_info *info, uint16_t cmd,
    uint32_t *flagsp)
{

	if (info == NULL)
		return (EINVAL);
	for (size_t i = 0; i < info->nops; i++) {
		if (info->ops[i].cmd == cmd) {
			if (flagsp != NULL)
				*flagsp = info->ops[i].flags;
			return (0);
		}
	}
	return (ENOENT);
}

void
cbl_family_info_free(cbl_family_info *info)
{

	if (info == NULL)
		return;
	free(info->ops);
	free(info->groups);
	free(info);
}

int
cbl_ping(cbl_conn *conn, int timeout_ms)
{
	static const uint8_t cookie[8] = "cblping";
	struct cblink_ctrl_ping_input in = {
		.cookie = { .p = cookie, .len = sizeof(cookie) } };
	struct cblink_ctrl_ping_output out = { 0 };
	cbl_msg *req, *rsp;
	cbl_yarena *a;
	int error;

	if (conn == NULL)
		return (EINVAL);
	if ((error = cbl_ctrl_msg(conn, CBL_CTRL_CMD_PING, "ping", &in, 0,
	    &req)) != 0)
		return (error);
	if ((a = cbl_yarena_new()) == NULL) {
		cbl_msg_free(req);
		return (ENOMEM);
	}
	if ((error = cbl_request(conn, req, &rsp, timeout_ms)) == 0 &&
	    (cbl_msg_ydecode(rsp, ctrl_io("ping", CBL_YN_OUTPUT), &out, a,
	    CBL_YD_STRICT, NULL, 0) != 0 || out.cookie.len != sizeof(cookie) ||
	    memcmp(out.cookie.p, cookie, sizeof(cookie)) != 0))
		error = EPROTO;
	cbl_msg_free(rsp);
	cbl_yarena_free(a);
	return (error);
}

int
cbl_hello(cbl_conn *conn)
{
	struct cblink_hello h, peer = { 0 };
	struct cblink_hello_limits l;
	cbl_msg *req, *rsp;
	cbl_yarena *a;
	int error;

	if (conn == NULL)
		return (EINVAL);
	our_hello(conn, &h, &l);
	if ((error = cbl_msg_new(conn->ctx, CBL_CTRL_FAMILY,
	    CBL_CTRL_CMD_HELLO, 0, &req)) != 0)
		return (error);
	if ((error = cbl_msg_put_ynode(req, cbl_fw_node("hello"), &h)) != 0) {
		cbl_msg_free(req);
		return (error);
	}
	if ((error = cbl_request(conn, req, &rsp, -1)) != 0) {
		cbl_msg_free(rsp);
		return (error);
	}
	if ((a = cbl_yarena_new()) == NULL) {
		cbl_msg_free(rsp);
		return (ENOMEM);
	}
	if (cbl_msg_ydecode(rsp, cbl_fw_node("hello"), &peer, a,
	    CBL_YD_STRICT, NULL, 0) != 0)
		error = EPROTO;
	else if (peer.limits != NULL && peer.limits->has_max_frame)
		set_peer_max_frame(conn, peer.limits->max_frame);
	cbl_yarena_free(a);
	cbl_msg_free(rsp);
	return (error);
}
