/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * cbl-kvy: the kv example in YANG (kv@2026-10-13.yang), its handlers
 * the ones cblink-gen -m server declares in kv.h and tables in
 * kv_server.c.  Until cblink 2's protocol serves the table (PLAN-SDN-YANG
 * 1.7), the program calls its handlers through it as the library will,
 * and says what came back: an edit, a get, the store's value in
 * YANG-CBOR and back, an action, an rpc, a notification.
 */

#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static void
hex(const char *what, const struct cbl_ybuf *b)
{

	printf("%s:", what);
	for (size_t i = 0; i < b->len; i++)
		printf(" %02x", b->p[i]);
	printf("\n");
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
	struct kv before = { 0 }, after = { .store = &st }, data = { 0 };
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
	const struct cbl_ynode *list;
	cbl_yarena *a;
	char why[256];

	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if (handler("store")->edit(NULL, &before, &after) != 0)
		errx(1, "edit");
	printf("edit: %zu entries\n", nstore);
	if (handler("store")->get(NULL, &data, a) != 0)
		errx(1, "get");
	printf("get: %zu entries, count %u\n", data.store->entry.n,
	    data.store->count);

	if (kv_store_encode(data.store, &b) != 0)
		errx(1, "encode");
	hex("store", &b);
	if (kv_store_decode(b.p, b.len, &back, a, CBL_YD_STRICT, why,
	    sizeof(why)) != 0)
		errx(1, "decode: %s", why);
	printf("decoded: %s ttl %u, %s%s\n", back.entry.v[0].key,
	    back.entry.v[0].ttl, back.entry.v[1].key,
	    back.entry.v[1].persistent ? " persistent" : "");
	cbl_ybuf_free(&b);

	list = NULL;
	{
		const struct cbl_ynode *n = cbl_yschema_node(kv_server.schema,
		    handler("store")->sid);

		for (uint32_t i = 0; n != NULL && i < n->nchild; i++)
			if (strcmp(n->child[i]->name, "entry") == 0)
				list = n->child[i];
	}
	if (list == NULL)
		errx(1, "no /kv:store/entry");
	for (int i = 0; i < 8; i++)
		iid[2 + i] = (unsigned char)(list->sid >> (56 - 8 * i));
	iid[10] = 0x65;		/* a text string of 5 */
	memcpy(iid + 11, "alpha", 5);
	if (handler("touch")->action(NULL, &target, NULL, &tout, a) != 0)
		errx(1, "touch");
	printf("touch: ttl %u\n", tout.ttl);
	if (handler("clear")->rpc(NULL, &cin, &cout, a) != 0)
		errx(1, "clear");
	printf("clear al: %u removed, %zu left\n", cout.removed, nstore);

	if (kv_changed_notification(&ch, &b) != 0)
		errx(1, "notification");
	hex("changed", &b);
	cbl_ybuf_free(&b);
	cbl_yarena_free(a);
	return (0);
}
