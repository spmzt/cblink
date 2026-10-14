/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Message builder.  The frame (header + CBOR body) is encoded directly
 * into one contiguous buffer with libcbor's low-level encoders.  Every
 * container head is reserved as one byte and widened on close only when
 * the element count reaches 24, so the output always uses definite
 * lengths and preferred (shortest) serialization.
 */

#include <errno.h>
#include <float.h>
#include <stdckdint.h>
#include <stdlib.h>
#include <string.h>

#include <cbor.h>

#include "cbl_impl.h"
#include "cbl_schema.h"

#define	CBL_HEAD_MAX	9	/* largest CBOR item head */

int
cbl_msg_alloc_empty(const struct cbl_limits *lim, cbl_msg **msgp)
{
	cbl_msg *msg;

	msg = calloc(1, sizeof(*msg));
	if (msg == NULL)
		return (ENOMEM);
	atomic_init(&msg->refs, 1);
	msg->lim = *lim;
	msg->err_miss = -1;
	msg->fwout.miss = -1;
	msg->empty.kind = CBL_K_NEST;
	msg->empty.inmap = 1;
	cbl_arena_init(&msg->arena);
	*msgp = msg;
	return (0);
}

int
cbl_msg_new(cbl_ctx *ctx, uint16_t family, uint16_t cmd, uint32_t flags,
    cbl_msg **msgp)
{
	struct cbl_limits lim;
	cbl_msg *msg;
	int error;

	if (ctx == NULL || msgp == NULL)
		return (EINVAL);
	pthread_mutex_lock(&ctx->mtx);
	lim = ctx->lim;
	pthread_mutex_unlock(&ctx->mtx);
	if ((error = cbl_msg_alloc_empty(&lim, &msg)) != 0)
		return (error);
	msg->hdr.version = CBL_PROTO_VERSION;
	msg->hdr.hdrlen = CBL_HDRLEN;
	msg->hdr.family = family;
	msg->hdr.cmd = cmd;
	msg->hdr.flags = flags;
	*msgp = msg;
	return (0);
}

void
cbl_msg_free(cbl_msg *msg)
{

	if (msg == NULL)
		return;
	if (atomic_fetch_sub(&msg->refs, 1) != 1)
		return;
	free(msg->buf);
	cbl_yarena_free(msg->ya);
	cbl_arena_free(&msg->arena);
	free(msg);
}

int
cbl_msg_ref(cbl_msg *msg)
{

	if (msg == NULL)
		return (EINVAL);
	atomic_fetch_add(&msg->refs, 1);
	return (0);
}

const char *
cbl_msg_errstr(const cbl_msg *msg)
{

	if (msg == NULL)
		return ("invalid message");
	if (msg->error == 0)
		return (NULL);
	return (msg->errstr != NULL ? msg->errstr : "error");
}

int
cbl_msg_fail(cbl_msg *msg, int error, const char *why)
{

	if (msg->error == 0) {
		msg->error = error;
		msg->errstr = why;
	}
	return (msg->error);
}

static void
msg_patch_hdr(cbl_msg *msg)
{

	if (msg->finalized)
		cbl_hdr_encode(msg->buf, &msg->hdr);
}

int
cbl_msg_set_seq(cbl_msg *msg, uint32_t seq)
{

	if (msg == NULL || msg->decoded)
		return (EINVAL);
	msg->hdr.seq = seq;
	msg_patch_hdr(msg);
	return (0);
}

int
cbl_msg_set_stream(cbl_msg *msg, uint32_t stream)
{

	if (msg == NULL || msg->decoded)
		return (EINVAL);
	msg->hdr.stream = stream;
	msg_patch_hdr(msg);
	return (0);
}

int
cbl_msg_set_flags(cbl_msg *msg, uint32_t flags)
{

	if (msg == NULL || msg->decoded)
		return (EINVAL);
	msg->hdr.flags = flags;
	msg_patch_hdr(msg);
	return (0);
}

/* Make room for "n" more bytes, bounded by max_frame. */
static int
msg_reserve(cbl_msg *msg, size_t n)
{
	size_t need, ncap, max;
	unsigned char *nbuf;

	max = msg->lim.v[CBL_LIM_MAX_FRAME];
	if (ckd_add(&need, msg->len, n) || need > max)
		return (cbl_msg_fail(msg, EMSGSIZE,
		    "message exceeds max_frame"));
	if (need <= msg->cap)
		return (0);
	ncap = msg->cap == 0 ? 256 : msg->cap;
	while (ncap < need)
		ncap *= 2;
	if (ncap > max)
		ncap = max;
	nbuf = realloc(msg->buf, ncap);
	if (nbuf == NULL)
		return (cbl_msg_fail(msg, ENOMEM, "out of memory"));
	msg->buf = nbuf;
	msg->cap = ncap;
	return (0);
}

static int
msg_push(cbl_msg *msg, bool is_map)
{
	struct cbl_bframe *f;
	int error;

	if ((uint64_t)msg->depth >= msg->lim.v[CBL_LIM_MAX_DEPTH])
		return (cbl_msg_fail(msg, ELOOP, "nesting exceeds max_depth"));
	if ((error = msg_reserve(msg, 1)) != 0)
		return (error);
	f = &msg->stack[msg->depth++];
	memset(f, 0, sizeof(*f));
	f->hoff = msg->len;
	f->is_map = is_map;
	f->lastkey = INT64_MIN;
	msg->buf[msg->len++] = 0;	/* placeholder head */
	return (0);
}

static int
msg_open_root(cbl_msg *msg)
{
	int error;

	if (msg->stack == NULL) {
		msg->stack = cbl_arena_alloc(&msg->arena,
		    msg->lim.v[CBL_LIM_MAX_DEPTH] * sizeof(*msg->stack));
		if (msg->stack == NULL)
			return (cbl_msg_fail(msg, ENOMEM, "out of memory"));
	}
	if ((error = msg_reserve(msg, CBL_HDRLEN)) != 0)
		return (error);
	msg->len = CBL_HDRLEN;
	return (msg_push(msg, true));
}

static int
msg_emit_raw(cbl_msg *msg, const void *p, size_t len)
{
	int error;

	if ((error = msg_reserve(msg, len)) != 0)
		return (error);
	if (len != 0)
		memcpy(msg->buf + msg->len, p, len);
	msg->len += len;
	return (0);
}

typedef size_t enc_f(uint64_t, unsigned char *, size_t);

/* Encode a head into a scratch buffer so exactly its size is reserved. */
static int
msg_emit_head(cbl_msg *msg, enc_f *enc, uint64_t v)
{
	unsigned char tmp[CBL_HEAD_MAX];

	return (msg_emit_raw(msg, tmp, enc(v, tmp, sizeof(tmp))));
}

/* Duplicate-key check; a linear scan only for out-of-order keys. */
static int
msg_note_key(cbl_msg *msg, struct cbl_bframe *f, int64_t key)
{
	int64_t *nk;
	uint32_t ncap;

	if (key <= f->lastkey) {
		for (uint32_t i = 0; i < f->nkeys; i++)
			if (f->keys[i] == key)
				return (cbl_msg_fail(msg, EEXIST,
				    "an item twice in the body"));
	} else
		f->lastkey = key;
	if (f->nkeys == f->capkeys) {
		ncap = f->capkeys == 0 ? 8 : f->capkeys * 2;
		nk = cbl_arena_alloc(&msg->arena, ncap * sizeof(*nk));
		if (nk == NULL)
			return (cbl_msg_fail(msg, ENOMEM, "out of memory"));
		if (f->nkeys != 0)
			memcpy(nk, f->keys, f->nkeys * sizeof(*nk));
		f->keys = nk;
		f->capkeys = ncap;
	}
	f->keys[f->nkeys++] = key;
	return (0);
}

/*
 * Start a top-level item: open the body's map if needed, emit its SID,
 * and account for limits.
 */
static int
msg_begin_item(cbl_msg *msg, int64_t key)
{
	struct cbl_bframe *f;
	int error;

	if (msg->error != 0)
		return (msg->error);
	if (msg->decoded)
		return (cbl_msg_fail(msg, EPERM, "message is read-only"));
	if (msg->finalized)
		return (cbl_msg_fail(msg, EBUSY, "message already encoded"));
	if (msg->depth == 0 && (error = msg_open_root(msg)) != 0)
		return (error);
	f = &msg->stack[msg->depth - 1];
	if ((error = msg_note_key(msg, f, key)) != 0 ||
	    (error = msg_emit_head(msg, cbor_encode_uint, (uint64_t)key)) != 0)
		return (error);
	if (++msg->nvalues > msg->lim.v[CBL_LIM_MAX_ATTRS])
		return (cbl_msg_fail(msg, E2BIG, "too many attributes"));
	if (f->count == UINT32_MAX)
		return (cbl_msg_fail(msg, E2BIG, "too many attributes"));
	f->count++;
	return (0);
}



/* Close the innermost container, widening its head if needed. */
static int
msg_pop(cbl_msg *msg)
{
	unsigned char head[CBL_HEAD_MAX];
	struct cbl_bframe *f;
	size_t n;
	int error;

	f = &msg->stack[msg->depth - 1];
	if (f->is_map)
		n = cbor_encode_map_start((size_t)f->count, head, sizeof(head));
	else
		n = cbor_encode_array_start((size_t)f->count, head,
		    sizeof(head));
	if (n > 1) {
		if ((error = msg_reserve(msg, n - 1)) != 0)
			return (error);
		memmove(msg->buf + f->hoff + n, msg->buf + f->hoff + 1,
		    msg->len - f->hoff - 1);
		msg->len += n - 1;
	}
	memcpy(msg->buf + f->hoff, head, n);
	msg->depth--;
	return (0);
}

/* Longest prefix of "s" not above "max" bytes ending on a UTF-8 boundary. */
static size_t
utf8_trunc(const char *s, size_t len, size_t max)
{

	if (len <= max)
		return (len);
	len = max;
	while (len > 0 && ((unsigned char)s[len] & 0xc0) == 0x80)
		len--;
	return (len);
}

int
cbl_msg_put_error(cbl_msg *msg, int code, const char *text,
    const struct cbl_path_elem *path, size_t pathlen, int miss_type)
{
	int error;

	if (msg == NULL)
		return (EINVAL);
	if (code < 0 || pathlen > CBL_PATH_MAX || (path == NULL && pathlen > 0))
		return (cbl_msg_fail(msg, EINVAL, "bad error attributes"));
	if (msg->decoded)
		return (cbl_msg_fail(msg, EPERM, "message is read-only"));
	if (msg->finalized)
		return (cbl_msg_fail(msg, EBUSY, "message already encoded"));
	/* Kept, and sent as the cblink error structure at encode. */
	if (text != NULL) {
		size_t len = utf8_trunc(text, strlen(text), CBL_ERRMSG_MAX);
		char *t;

		if ((t = cbl_arena_alloc(&msg->arena, len + 1)) == NULL)
			return (cbl_msg_fail(msg, ENOMEM, "out of memory"));
		memcpy(t, text, len);
		t[len] = '\0';
		text = t;
	}
	if ((error = cbl_fw_error(msg, code, text, path, pathlen,
	    miss_type)) != 0)
		return (error);
	return (0);
}

/*
 * Version 2: a top-level item {sid: value}, the value YANG-CBOR as it is
 * (one well-formed item; the receiver checks it, as any body).
 */
int
cbl_msg_put_sid_raw(cbl_msg *msg, uint64_t sid, const void *cbor,
    size_t len)
{
	int error;

	if (msg == NULL || cbor == NULL || len == 0)
		return (EINVAL);
	if (sid == 0 || sid > INT64_MAX)
		return (cbl_msg_fail(msg, EINVAL, "a SID is 1 to 2^63 - 1"));
	if ((error = msg_begin_item(msg, (int64_t)sid)) != 0)
		return (error);
	return (msg_emit_raw(msg, cbor, len));
}

int
cbl_msg_put_ynode(cbl_msg *msg, const struct cbl_ynode *n, const void *p)
{
	struct cbl_ybuf b = { 0 };
	int error;

	if (msg == NULL || n == NULL || p == NULL)
		return (EINVAL);
	if ((error = cbl_yencode(n, p, &b)) != 0)
		return (cbl_msg_fail(msg, error, "cannot encode the value"));
	/* An input or an output goes under its rpc's SID (CORECONF). */
	error = cbl_msg_put_sid_raw(msg, cbl_ynode_base(n), b.p, b.len);
	cbl_ybuf_free(&b);
	return (error);
}

int
cbl_msg_put_ymember(cbl_msg *msg, const struct cbl_ynode *n,
    const void *parent)
{
	struct cbl_ybuf b = { 0 };
	int error;

	if (msg == NULL || n == NULL || parent == NULL)
		return (EINVAL);
	if ((error = cbl_yencode_member(n, parent, &b)) == ENOENT)
		return (0);	/* not there: nothing to say */
	if (error != 0)
		return (cbl_msg_fail(msg, error, "cannot encode the value"));
	error = cbl_msg_put_sid_raw(msg, n->sid, b.p, b.len);
	cbl_ybuf_free(&b);
	return (error);
}

int
cbl_msg_put_ynull(cbl_msg *msg, uint64_t sid)
{
	static const uint8_t null = 0xf6;

	return (cbl_msg_put_sid_raw(msg, sid, &null, 1));
}

int
cbl_msg_sid_raw(const cbl_msg *msg, uint64_t sid, const void **pp,
    size_t *lenp)
{
	const cbl_attr *a;

	if (msg == NULL || pp == NULL || lenp == NULL || sid == 0 ||
	    sid > INT64_MAX || !msg->decoded)
		return (EINVAL);
	if ((a = cbl_map_lookup(cbl_msg_body(msg), (int64_t)sid)) == NULL)
		return (ENOENT);
	*pp = msg->buf + msg->hdr.hdrlen + a->off;
	*lenp = a->len;
	return (0);
}

int
cbl_msg_ydecode(const cbl_msg *msg, const struct cbl_ynode *n, void *p,
    cbl_yarena *a, int flags, char *why, size_t whylen)
{
	const void *v;
	size_t len;
	int error;

	if (why != NULL && whylen > 0)
		why[0] = '\0';
	if (n == NULL || p == NULL || a == NULL)
		return (EINVAL);
	error = cbl_msg_sid_raw(msg, cbl_ynode_base(n), &v, &len);
	/* A notification sent: in the cblink:notification envelope. */
	if (error == ENOENT && n->kind == CBL_YN_NOTIF) {
		struct cbl_ynotif nt;

		if (cbl_msg_ynotif(msg, &nt, a) != 0 || nt.sid != n->sid)
			return (ENOENT);
		memset(p, 0, n->size);
		return (cbl_ydecode(n, nt.content, nt.len, p, a, flags, why,
		    whylen));
	}
	if (error != 0)
		return (error);
	memset(p, 0, n->size);
	/* No input or no output: null, as CORECONF sends it. */
	if ((n->kind == CBL_YN_INPUT || n->kind == CBL_YN_OUTPUT) &&
	    len == 1 && *(const uint8_t *)v == 0xf6)
		return (0);
	return (cbl_ydecode(n, v, len, p, a, flags, why, whylen));
}

int
cbl_msg_ydecode_member(const cbl_msg *msg, const struct cbl_ynode *n,
    void *parent, cbl_yarena *a, int flags, char *why, size_t whylen)
{
	const void *v;
	size_t len;
	int error;

	if (why != NULL && whylen > 0)
		why[0] = '\0';
	if (n == NULL || parent == NULL || a == NULL)
		return (EINVAL);
	if ((error = cbl_msg_sid_raw(msg, n->sid, &v, &len)) != 0)
		return (error);
	return (cbl_ydecode_member(n, v, len, parent, a, flags, why,
	    whylen));
}

int
cbl_msg_put_cookie(cbl_msg *msg, const void *p, size_t len)
{

	if (msg == NULL)
		return (EINVAL);
	if (len > CBL_COOKIE_MAX || (p == NULL && len != 0))
		return (cbl_msg_fail(msg, EINVAL, "bad cookie"));
	return (cbl_fw_cookie(msg, p, len));
}

/* Finish the body and write the header.  Idempotent. */
int
cbl_msg_encode(cbl_msg *msg, const void **framep, size_t *lenp)
{
	int error;

	if (msg == NULL)
		return (EINVAL);
	if (msg->error != 0)
		return (msg->error);
	if (!msg->finalized) {
		if (msg->decoded)
			return (EPERM);
		/* The error asked of it, written last. */
		if ((error = cbl_fw_flush(msg)) != 0)
			return (error);
		if (msg->depth == 1 && (error = msg_pop(msg)) != 0)
			return (error);
		if (msg->len == 0) {
			if ((error = msg_reserve(msg, CBL_HDRLEN)) != 0)
				return (error);
			msg->len = CBL_HDRLEN;
		}
		msg->hdr.length = (uint32_t)msg->len;
		msg->finalized = true;
		/*
		 * Written once: an encoded message may be shared by several
		 * connections (notifications); later header changes go
		 * through the cbl_msg_set_*() setters.
		 */
		cbl_hdr_encode(msg->buf, &msg->hdr);
	}
	if (!cbl_flags_valid(msg->hdr.flags, msg->hdr.stream))
		return (EINVAL);
	if (framep != NULL)
		*framep = msg->buf;
	if (lenp != NULL)
		*lenp = msg->len;
	return (0);
}

int
cbl_msg_error(const cbl_msg *msg)
{

	return (msg != NULL ? msg->error : EINVAL);
}
