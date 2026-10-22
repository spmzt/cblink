/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * cbl-kv: the kv example in YANG (kv@2026-10-13.yang), its handlers
 * the ones cblink-gen -m server declares in kv.h and tables in
 * kv_server.c, served by family 1 ("cblink.yang") on a unix: socket of
 * its own: a client edits the store, reads it back (its value in
 * YANG-CBOR, and decoded), fetches the .sid file, and calls an rpc, and
 * the program says what came back.  The action is called through the table, as family 1 does
 * not carry actions yet.  A notification is shown as bytes, then sent
 * to the client, which subscribed to family 1's group "notify".
 */

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kv.h"

#define	MAX_ENTRIES	64

static struct entry {
	char		 key[256];
	unsigned char	 value[64];
	size_t		 vlen;
	bool		 persistent;
	uint32_t	 ttl;
} store[MAX_ENTRIES];
static size_t	nstore;

static char *
astrdup(cbl_yarena *a, const char *s)
{
	char *p;

	if ((p = cbl_yarena_alloc(a, strlen(s) + 1)) != NULL)
		memcpy(p, s, strlen(s) + 1);
	return (p);
}

/* GET of /kv:store: the entries, and their count. */
int
kv_store_get(cbl_req *req, struct kv *data, cbl_yarena *a)
{
	struct kv_store *st;
	struct kv_store_entry *v;

	(void)req;
	if ((st = cbl_yarena_alloc(a, sizeof(*st))) == NULL ||
	    (v = cbl_yarena_alloc(a, nstore * sizeof(*v))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < nstore; i++) {
		v[i].key = astrdup(a, store[i].key);
		v[i].value.p = store[i].value;
		v[i].value.len = store[i].vlen;
		v[i].has_persistent = true;
		v[i].persistent = store[i].persistent;
		v[i].has_ttl = store[i].ttl != 0;
		v[i].ttl = store[i].ttl;
	}
	st->entry.n = nstore;
	st->entry.v = v;
	st->has_count = true;
	st->count = (uint32_t)nstore;
	data->store = st;
	return (0);
}

/* An edit of /kv:store: what it is after, kept. */
int
kv_store_edit(cbl_req *req, const struct kv *before, const struct kv *after)
{
	const struct kv_store_entry *e;

	(void)req;
	(void)before;
	nstore = 0;
	for (size_t i = 0; after->store != NULL && i <
	    after->store->entry.n && nstore < MAX_ENTRIES; i++) {
		e = &after->store->entry.v[i];
		if (strlen(e->key) >= sizeof(store[0].key) ||
		    e->value.len > sizeof(store[0].value))
			return (EINVAL);
		memset(&store[nstore], 0, sizeof(store[nstore]));
		strcpy(store[nstore].key, e->key);
		if (e->value.len > 0)
			memcpy(store[nstore].value, e->value.p, e->value.len);
		store[nstore].vlen = e->value.len;
		store[nstore].persistent = e->has_persistent && e->persistent;
		store[nstore].ttl = e->has_ttl ? e->ttl : 0;
		nstore++;
	}
	return (0);
}

/* touch, an action on an entry: its time to live begins again. */
int
kv_store_entry_touch_action(cbl_req *req, const struct cbl_bytes *target,
    const struct kv_store_entry_touch_input *in,
    struct kv_store_entry_touch_output *out, cbl_yarena *a)
{

	(void)req;
	(void)in;
	(void)a;
	if (target == NULL || target->len == 0)
		return (EINVAL);
	out->has_ttl = true;
	out->ttl = 300;
	return (0);
}

/* clear: the entries whose keys begin with the prefix go. */
int
kv_clear_rpc(cbl_req *req, const struct kv_clear_input *in,
    struct kv_clear_output *out, cbl_yarena *a)
{
	size_t k = 0, len;

	(void)req;
	(void)a;
	len = in->prefix != NULL ? strlen(in->prefix) : 0;
	for (size_t i = 0; i < nstore; i++)
		if (strncmp(store[i].key, in->prefix != NULL ? in->prefix :
		    "", len) != 0)
			store[k++] = store[i];
	out->has_removed = true;
	out->removed = (uint32_t)(nstore - k);
	nstore = k;
	return (0);
}

/* The handlers of the node named name, through the table. */
static const struct cbl_yhandler *
handler(const char *name)
{
	const struct cbl_ynode *n;

	for (uint32_t i = 0; i < kv_server.nhandler; i++) {
		n = cbl_yschema_node(kv_server.schema,
		    kv_server.handler[i].sid);
		if (n != NULL && strcmp(n->name, name) == 0)
			return (&kv_server.handler[i]);
	}
	errx(1, "no handler for %s", name);
}

/* The module's top-level node named name. */
static const struct cbl_ynode *
node(const char *name)
{
	const struct cbl_ymodule *m = kv_server.schema->mod[0];

	for (uint32_t i = 0; i < m->ntop; i++)
		if (strcmp(m->top[i]->name, name) == 0)
			return (m->top[i]);
	errx(1, "no node %s", name);
}

static void
hex(const char *what, const void *p, size_t len)
{

	printf("%s:", what);
	for (size_t i = 0; i < len; i++)
		printf(" %02x", ((const unsigned char *)p)[i]);
	printf("\n");
}

static void *
serve(void *loop)
{

	(void)cbl_loop_run(loop);
	return (NULL);
}

static cbl_msg *
call(cbl_conn *c, enum cbl_ycmd cmd, cbl_msg **mp)
{
	cbl_msg *r;
	int error;

	if ((error = cbl_request(c, *mp, &r, 5000)) != 0)
		errx(1, "command %d: %s: %s", cmd, strerror(error),
		    r != NULL && cbl_msg_err_str(r) != NULL ?
		    cbl_msg_err_str(r) : "");
	*mp = NULL;
	return (r);
}

/* A notification heard: which, and its key and what. */
static void
heard(cbl_conn *conn, cbl_msg *m, void *arg)
{
	struct kv_changed ch = { 0 };
	cbl_yarena *a;
	int *n = arg;

	(void)conn;
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	/* ENOENT: another notification than this one. */
	if (kv_changed_parse(m, &ch, a, CBL_YD_STRICT, NULL, 0) != 0)
		errx(1, "not the notification sent");
	printf("notified: changed %s %s\n", ch.key,
	    ch.what == KV_CHANGED_WHAT_DELETED ? "deleted" : "set");
	cbl_yarena_free(a);
	(*n)++;
}

static cbl_msg *
request(cbl_ctx *ctx, enum cbl_ycmd cmd)
{
	cbl_msg *m;

	if (cbl_msg_new(ctx, CBL_YANG_FAMILY, cmd, 0, &m) != 0)
		errx(1, "cbl_msg_new");
	return (m);
}

int
main(void)
{
	static unsigned char hello[] = "hello";
	struct kv_store_entry e[2] = {
		{ .key = "alpha", .value = { hello, 5 },
		    .has_ttl = true, .ttl = 60 },
		{ .key = "beta", .has_persistent = true, .persistent = true },
	};
	struct kv_store st = { .entry = { 2, e } };
	struct kv_store back;
	struct kv_clear_input cin = { .prefix = "al" };
	struct kv_clear_output cout = { 0 };
	struct kv_store_entry_touch_output tout = { 0 };
	struct kv_changed ch = { .key = "beta",
	    .has_what = true, .what = KV_CHANGED_WHAT_DELETED };
	struct cbl_ybuf b = { 0 };
	/*
	 * /kv:store/entry[key="alpha"], an instance-identifier as RFC 9254
	 * section 6.13.1 has it: [the list's SID, its key].
	 */
	unsigned char iid[16] = { 0x82, 0x1b };
	struct cbl_bytes target = { iid, sizeof(iid) };
	const struct cbl_ynode *kvs, *list;
	char dir[] = "/tmp/cbl-kv.XXXXXX", uri[64], why[256];
	cbl_ctx *sctx, *cctx;
	cbl_listener *l;
	cbl_loop *loop;
	cbl_conn *c;
	cbl_msg *m, *r;
	cbl_yarena *a;
	struct pollfd pfd;
	cbl_dump *d;
	bool same = false;
	int nfiles = 0;
	pthread_t thr;
	cbl_sub *sub;
	uint64_t sid;
	int error, events, timeout, nheard = 0;
	const void *v;
	size_t len;

	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	kvs = node("store");

	/* The server: kv's table, served by family 1. */
	if (mkdtemp(dir) == NULL)
		err(1, "mkdtemp");
	snprintf(uri, sizeof(uri), "unix:%s/s", dir);
	if (cbl_ctx_new(&sctx) != 0 || cbl_ctx_new(&cctx) != 0)
		errx(1, "cbl_ctx_new");
	if (cbl_yserver_add(sctx, &kv_server, NULL) != 0)
		errx(1, "cbl_yserver_add");
	if (cbl_loop_new(sctx, &loop) != 0 ||
	    cbl_listener_new(sctx, uri, CBL_PLAINTEXT, &l) != 0 ||
	    cbl_listener_start(l, loop) != 0)
		errx(1, "%s: cannot listen", uri);
	if (pthread_create(&thr, NULL, serve, loop) != 0)
		errx(1, "pthread_create");
	if (cbl_conn_new(cctx, uri, CBL_PLAINTEXT, &c) != 0 ||
	    cbl_conn_connect(c) != 0)
		errx(1, "%s: cannot connect", uri);

	/* EDIT: the store, its two entries; kv_store_put() as kv.h has it. */
	m = request(cctx, CBL_YCMD_EDIT);
	if (kv_store_put(m, &st) != 0)
		errx(1, "edit");
	cbl_msg_free(call(c, CBL_YCMD_EDIT, &m));
	printf("edit: %zu entries\n", nstore);

	/* GET: the store, as YANG-CBOR and decoded. */
	m = request(cctx, CBL_YCMD_GET);
	sid = kvs->sid;
	if (cbl_msg_put_yget(m, &sid, 1) != 0)
		errx(1, "get");
	r = call(c, CBL_YCMD_GET, &m);
	if (cbl_msg_sid_raw(r, kvs->sid, &v, &len) != 0)
		errx(1, "get: no store");
	if (kv_store_parse(r, &back, a, CBL_YD_STRICT, why, sizeof(why)) != 0)
		errx(1, "decode: %s", why);
	printf("get: %zu entries, count %u\n", back.entry.n, back.count);
	hex("store", v, len);
	printf("decoded: %s ttl %u, %s%s\n", back.entry.v[0].key,
	    back.entry.v[0].ttl, back.entry.v[1].key,
	    back.entry.v[1].persistent ? " persistent" : "");
	cbl_msg_free(r);

	/* GET-SID: the .sid file the server numbers kv by. */
	if (cbl_msg_new(cctx, CBL_YANG_FAMILY, CBL_YCMD_GET_SID, CBL_F_DUMP,
	    &m) != 0 || cbl_dump_start(c, m, &d) != 0)
		errx(1, "get-sid");
	while (cbl_dump_next(d, &r) == 0 && r != NULL) {
		if (cbl_msg_sid_raw(r, CBL_YSID_FILE, &v, &len) != 0)
			errx(1, "get-sid: not a sid-file");
		same = len == kv_server.sidfile[0].len &&
		    memcmp(v, kv_server.sidfile[0].cbor, len) == 0;
		nfiles++;
	}
	cbl_dump_free(d);
	printf("get-sid: %d file, %zu bytes, %s\n", nfiles, len,
	    same ? "as the table has it" : "not the table's");

	/* touch, an action: through the table, as family 1 has none yet. */
	list = NULL;
	for (uint32_t i = 0; i < kvs->nchild; i++)
		if (strcmp(kvs->child[i]->name, "entry") == 0)
			list = kvs->child[i];
	if (list == NULL)
		errx(1, "no /kv:store/entry");
	for (int i = 0; i < 8; i++)
		iid[2 + i] = (unsigned char)(list->sid >> (56 - 8 * i));
	iid[10] = 0x65;		/* a text string of 5 */
	memcpy(iid + 11, "alpha", 5);
	if (handler("touch")->action(NULL, &target, NULL, &tout, a) != 0)
		errx(1, "touch");
	printf("touch: ttl %u\n", tout.ttl);

	/* RPC: clear, called through family 1 (kv_clear_call()). */
	if ((error = kv_clear_call(c, &cin, &cout, a, 5000)) != 0)
		errc(1, error, "clear");
	printf("clear al: %u removed, %zu left\n", cout.removed, nstore);

	if (kv_changed_notification(&ch, &b) != 0)
		errx(1, "notification");
	hex("changed", b.p, b.len);
	cbl_ybuf_free(&b);

	/* The notification sent to who subscribed, the client. */
	if (cbl_subscribe(c, "cblink.yang", "notify", heard, &nheard,
	    &sub) != 0)
		errx(1, "subscribe");
	if (kv_changed_notify(sctx, &ch) != 0)
		errx(1, "notify");
	while (nheard == 0 && cbl_conn_is_open(c)) {
		cbl_conn_interest(c, &events, &timeout);
		pfd.fd = cbl_conn_fd(c);
		pfd.events = POLLIN | ((events & CBL_EV_WRITE) ? POLLOUT : 0);
		if (poll(&pfd, 1, 5000) == 0)
			errx(1, "no notification");
		(void)cbl_conn_process(c,
		    ((pfd.revents & POLLIN) ? CBL_EV_READ : 0) |
		    ((pfd.revents & POLLOUT) ? CBL_EV_WRITE : 0));
	}
	(void)cbl_unsubscribe(sub);

	cbl_conn_free(c);
	cbl_loop_stop(loop);
	(void)pthread_join(thr, NULL);
	cbl_listener_free(l);
	cbl_loop_free(loop);
	cbl_ctx_free(cctx);
	cbl_ctx_free(sctx);
	(void)unlink(uri + 5);
	(void)rmdir(dir);
	cbl_yarena_free(a);
	return (0);
}
