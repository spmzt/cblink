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

void *
cbl_msg_alloc(cbl_msg *msg, size_t len)
{

	if (msg == NULL)
		return (NULL);
	return (cbl_arena_alloc(&msg->arena, len));
}

char *
cbl_msg_strdup(cbl_msg *msg, const char *s)
{
	size_t len;
	char *p;

	if (msg == NULL || s == NULL)
		return (NULL);
	len = strlen(s);
	if ((p = cbl_arena_alloc(&msg->arena, len + 1)) != NULL)
		memcpy(p, s, len);
	return (p);
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
				    "duplicate attribute in map"));
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
 * Start a value: open the root map if needed, emit the key when the
 * current container is a map, and account for limits.  "fw" allows the
 * negative framework keys.
 */
static int
msg_begin_value(cbl_msg *msg, int64_t key, bool fw)
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
	if (f->is_map) {
		if (fw) {
			if (key >= 0 || key < CBL_FW_MIN)
				return (cbl_msg_fail(msg, EINVAL,
				    "invalid framework key"));
		} else if (key < CBL_ATTR_MIN || key > CBL_ATTR_MAX)
			return (cbl_msg_fail(msg, EINVAL,
			    "attribute type must be 1..65535 inside a map"));
		if ((error = msg_note_key(msg, f, key)) != 0)
			return (error);
		if (key >= 0)
			error = msg_emit_head(msg, cbor_encode_uint,
			    (uint64_t)key);
		else
			error = msg_emit_head(msg, cbor_encode_negint,
			    (uint64_t)(-1 - key));
		if (error != 0)
			return (error);
	} else if (key != CBL_ELEM)
		return (cbl_msg_fail(msg, EINVAL,
		    "array elements must use CBL_ELEM"));
	if (++msg->nvalues > msg->lim.v[CBL_LIM_MAX_ATTRS])
		return (cbl_msg_fail(msg, E2BIG, "too many attributes"));
	if (f->count == UINT32_MAX)
		return (cbl_msg_fail(msg, E2BIG, "too many attributes"));
	f->count++;
	return (0);
}



static size_t
enc_text(uint64_t v, unsigned char *p, size_t len)
{

	return (cbor_encode_string_start((size_t)v, p, len));
}

static size_t
enc_bytes(uint64_t v, unsigned char *p, size_t len)
{

	return (cbor_encode_bytestring_start((size_t)v, p, len));
}

static size_t
enc_bool(uint64_t v, unsigned char *p, size_t len)
{

	return (cbor_encode_bool(v != 0, p, len));
}

static size_t
enc_null(uint64_t v __unused, unsigned char *p, size_t len)
{

	return (cbor_encode_null(p, len));
}

static int
put_uint_k(cbl_msg *msg, int64_t key, bool fw, uint64_t v)
{
	int error;

	if ((error = msg_begin_value(msg, key, fw)) != 0)
		return (error);
	return (msg_emit_head(msg, cbor_encode_uint, v));
}

static int
put_text_k(cbl_msg *msg, int64_t key, bool fw, const char *s, size_t len)
{
	int error;

	if ((error = msg_begin_value(msg, key, fw)) != 0)
		return (error);
	if (memchr(s, '\0', len) != NULL ||
	    !cbl_utf8_valid((const unsigned char *)s, len))
		return (cbl_msg_fail(msg, EINVAL,
		    "text must be UTF-8 without NUL"));
	if ((error = msg_emit_head(msg, enc_text, len)) != 0)
		return (error);
	return (msg_emit_raw(msg, s, len));
}

static int
put_bytes_k(cbl_msg *msg, int64_t key, bool fw, const void *p, size_t len)
{
	int error;

	if ((error = msg_begin_value(msg, key, fw)) != 0)
		return (error);
	if ((error = msg_emit_head(msg, enc_bytes, len)) != 0)
		return (error);
	return (msg_emit_raw(msg, p, len));
}

int
cbl_put_uint(cbl_msg *msg, uint16_t type, uint64_t v)
{

	if (msg == NULL)
		return (EINVAL);
	return (put_uint_k(msg, type, false, v));
}

int
cbl_put_int(cbl_msg *msg, uint16_t type, int64_t v)
{
	int error;

	if (msg == NULL)
		return (EINVAL);
	if (v >= 0)
		return (put_uint_k(msg, type, false, (uint64_t)v));
	if ((error = msg_begin_value(msg, type, false)) != 0)
		return (error);
	return (msg_emit_head(msg, cbor_encode_negint, (uint64_t)(-1 - v)));
}

int
cbl_put_bool(cbl_msg *msg, uint16_t type, bool v)
{
	int error;

	if (msg == NULL)
		return (EINVAL);
	if ((error = msg_begin_value(msg, type, false)) != 0)
		return (error);
	return (msg_emit_head(msg, enc_bool, v));
}

int
cbl_put_flag(cbl_msg *msg, uint16_t type)
{

	return (cbl_put_bool(msg, type, true));
}

int
cbl_put_null(cbl_msg *msg, uint16_t type)
{
	int error;

	if (msg == NULL)
		return (EINVAL);
	if ((error = msg_begin_value(msg, type, false)) != 0)
		return (error);
	return (msg_emit_head(msg, enc_null, 0));
}

int
cbl_put_double(cbl_msg *msg, uint16_t type, double v)
{
	unsigned char tmp[CBL_HEAD_MAX];
	size_t n;
	int error;

	if (msg == NULL)
		return (EINVAL);
	if ((error = msg_begin_value(msg, type, false)) != 0)
		return (error);
	/*
	 * Shortest exact float width; NaN, infinities and anything a float
	 * cannot hold (converting it would be undefined) stay double.
	 */
	if (v >= -FLT_MAX && v <= FLT_MAX && (double)(float)v == v)
		n = cbor_encode_single((float)v, tmp, sizeof(tmp));
	else
		n = cbor_encode_double(v, tmp, sizeof(tmp));
	return (msg_emit_raw(msg, tmp, n));
}

int
cbl_put_str(cbl_msg *msg, uint16_t type, const char *s)
{

	if (msg == NULL)
		return (EINVAL);
	if (s == NULL)
		return (cbl_msg_fail(msg, EINVAL, "NULL string"));
	return (put_text_k(msg, type, false, s, strlen(s)));
}

int
cbl_put_strn(cbl_msg *msg, uint16_t type, const char *s, size_t len)
{

	if (msg == NULL)
		return (EINVAL);
	if (s == NULL && len != 0)
		return (cbl_msg_fail(msg, EINVAL, "NULL string"));
	return (put_text_k(msg, type, false, s != NULL ? s : "", len));
}

int
cbl_put_bytes(cbl_msg *msg, uint16_t type, const void *p, size_t len)
{

	if (msg == NULL)
		return (EINVAL);
	if (p == NULL && len != 0)
		return (cbl_msg_fail(msg, EINVAL, "NULL buffer"));
	return (put_bytes_k(msg, type, false, p, len));
}

static int
start_k(cbl_msg *msg, int64_t key, bool fw, bool is_map)
{
	int error;

	if ((error = msg_begin_value(msg, key, fw)) != 0)
		return (error);
	return (msg_push(msg, is_map));
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

static int
end_k(cbl_msg *msg, bool is_map)
{

	if (msg == NULL)
		return (EINVAL);
	if (msg->error != 0)
		return (msg->error);
	if (msg->decoded || msg->finalized)
		return (cbl_msg_fail(msg, EBUSY, "message is not being built"));
	if (msg->depth <= 1 || msg->stack[msg->depth - 1].is_map != is_map)
		return (cbl_msg_fail(msg, EINVAL, is_map ?
		    "cbl_nest_end() without matching cbl_nest_start()" :
		    "cbl_array_end() without matching cbl_array_start()"));
	return (msg_pop(msg));
}

int
cbl_nest_start(cbl_msg *msg, uint16_t type)
{

	if (msg == NULL)
		return (EINVAL);
	return (start_k(msg, type, false, true));
}

int
cbl_nest_end(cbl_msg *msg)
{

	return (end_k(msg, true));
}

int
cbl_array_start(cbl_msg *msg, uint16_t type)
{

	if (msg == NULL)
		return (EINVAL);
	return (start_k(msg, type, false, false));
}

int
cbl_array_end(cbl_msg *msg)
{

	return (end_k(msg, false));
}

/* Re-encode a decoded subtree; framework and invalid keys are dropped. */
static int
put_attr_k(cbl_msg *msg, int64_t key, bool fw, const cbl_attr *a)
{
	const cbl_attr *c;
	int error;

	switch (a->kind) {
	case CBL_K_UINT:
		return (put_uint_k(msg, key, fw, a->v.u));
	case CBL_K_INT:
		if ((error = msg_begin_value(msg, key, fw)) != 0)
			return (error);
		return (msg_emit_head(msg, cbor_encode_negint,
		    (a->nflags & CBL_NF_NEGBIG) != 0 ? a->v.u :
		    (uint64_t)(-1 - a->v.i)));
	case CBL_K_BOOL:
		if ((error = msg_begin_value(msg, key, fw)) != 0)
			return (error);
		return (msg_emit_head(msg, enc_bool, a->v.b));
	case CBL_K_NULL:
		if ((error = msg_begin_value(msg, key, fw)) != 0)
			return (error);
		return (msg_emit_head(msg, enc_null, 0));
	case CBL_K_FLOAT:
		if (fw)
			return (cbl_msg_fail(msg, EINVAL,
			    "bad framework value"));
		return (cbl_put_double(msg, (uint16_t)key, a->v.d));
	case CBL_K_TEXT:
		return (put_text_k(msg, key, fw, (const char *)a->v.s.p,
		    a->v.s.len));
	case CBL_K_BYTES:
		return (put_bytes_k(msg, key, fw, a->v.s.p, a->v.s.len));
	case CBL_K_NEST:
	case CBL_K_ARRAY:
		if ((error = start_k(msg, key, fw, a->kind == CBL_K_NEST)) != 0)
			return (error);
		for (uint32_t i = 0; i < a->count; i++) {
			c = &a->child[i];
			if (c->inmap &&
			    (c->key < CBL_ATTR_MIN || c->key > CBL_ATTR_MAX))
				continue;
			if ((error = put_attr_k(msg, c->inmap ? c->key :
			    CBL_ELEM, false, c)) != 0)
				return (error);
		}
		return (msg_pop(msg));
	default:
		return (cbl_msg_fail(msg, EINVAL, "bad attribute"));
	}
}

int
cbl_put_attr(cbl_msg *msg, uint16_t type, const cbl_attr *a)
{

	if (msg == NULL)
		return (EINVAL);
	if (a == NULL)
		return (cbl_msg_fail(msg, EINVAL, "NULL attribute"));
	return (put_attr_k(msg, type, false, a));
}

/* Framework attributes (negative keys). */
int
cbl_msg_put_fw_uint(cbl_msg *msg, int key, uint64_t v)
{

	return (put_uint_k(msg, key, true, v));
}

int
cbl_msg_put_fw_str(cbl_msg *msg, int key, const char *s)
{

	return (put_text_k(msg, key, true, s, strlen(s)));
}

int
cbl_msg_put_fw_bytes(cbl_msg *msg, int key, const void *p, size_t len)
{

	return (put_bytes_k(msg, key, true, p, len));
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
	if (code > 0 && (error = put_uint_k(msg, CBL_FW_CODE, true,
	    (uint64_t)code)) != 0)
		return (error);
	if (text != NULL && (error = put_text_k(msg, CBL_FW_MSG, true, text,
	    utf8_trunc(text, strlen(text), CBL_ERRMSG_MAX))) != 0)
		return (error);
	if (pathlen > 0) {
		if ((error = start_k(msg, CBL_FW_PATH, true, false)) != 0)
			return (error);
		for (size_t i = 0; i < pathlen; i++) {
			if (path[i].index) {
				if ((error = start_k(msg, CBL_ELEM, false,
				    false)) != 0 ||
				    (error = put_uint_k(msg, CBL_ELEM, false,
				    path[i].v)) != 0 ||
				    (error = msg_pop(msg)) != 0)
					return (error);
			} else if ((error = put_uint_k(msg, CBL_ELEM, false,
			    path[i].v)) != 0)
				return (error);
		}
		if ((error = msg_pop(msg)) != 0)
			return (error);
	}
	if (miss_type >= 0 && (error = put_uint_k(msg, CBL_FW_MISS_TYPE, true,
	    (uint64_t)miss_type)) != 0)
		return (error);
	return (0);
}

int
cbl_msg_put_cookie(cbl_msg *msg, const void *p, size_t len)
{

	if (msg == NULL)
		return (EINVAL);
	if (len > CBL_COOKIE_MAX || (p == NULL && len != 0))
		return (cbl_msg_fail(msg, EINVAL, "bad cookie"));
	return (put_bytes_k(msg, CBL_FW_COOKIE, true, p, len));
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
		if (msg->depth > 1)
			return (cbl_msg_fail(msg, EINVAL,
			    "unterminated nest or array"));
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
