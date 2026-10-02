/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Body decoder (docs/WIRE-FORMAT.md sections 5 and 11).
 *
 * The body is decoded twice with libcbor's streaming decoder, which never
 * allocates.  Pass 1 checks well-formedness, the strict profile
 * (definite lengths, no tags, integer keys, UTF-8) and the limits
 * (max_depth, max_attrs), and counts the values.  Only then does pass 2
 * allocate the exact node array from the message arena and fill it in.
 * Strings are not copied: nodes point into the frame buffer.
 */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <cbor.h>

#include "cbl_impl.h"

struct dec_level {
	uint64_t	 remaining;	/* values (maps: pairs) still due */
	bool		 is_map;
	bool		 want_key;
	int64_t		 key;
	cbl_attr	*node;		/* pass 2 */
	uint32_t	 next;		/* pass 2: next child slot */
};

struct dec {
	int			 pass;
	const struct cbl_limits	*lim;
	size_t			 bodylen;
	struct dec_level	 st[CBL_DEPTH_HARD_MAX];
	int			 depth;
	bool			 root_done;
	uint32_t		 nvalues;
	int			 error;
	const char		*why;
	cbl_attr		*pool;		/* pass 2 */
	uint32_t		 pool_used;
	uint32_t		 pool_size;
};

static void
dec_fail(struct dec *d, int error, const char *why)
{

	if (d->error == 0) {
		d->error = error;
		d->why = why;
	}
}

static int
key_cmp(const void *a, const void *b)
{
	const cbl_attr *x = a, *y = b;

	return ((x->key > y->key) - (x->key < y->key));
}

/*
 * Strictly ascending keys (what this library's builder writes) are
 * sorted and free of duplicates already.
 */
static bool
keys_ascending(const cbl_attr *n)
{

	for (uint32_t i = 1; i < n->count; i++)
		if (n->child[i].key <= n->child[i - 1].key)
			return (false);
	return (true);
}

static void
dec_pop_ready(struct dec *d)
{
	struct dec_level *top;
	cbl_attr *n;

	while (d->depth > 0) {
		top = &d->st[d->depth - 1];
		if (top->remaining != 0 || (top->is_map && !top->want_key))
			return;
		n = top->node;
		if (d->pass == 2 && top->is_map && n->count > 1 &&
		    !keys_ascending(n)) {
			/*
			 * heapsort(3): O(n log n) whatever order a peer
			 * chose, and no allocation.
			 */
			if (heapsort(n->child, n->count, sizeof(cbl_attr),
			    key_cmp) != 0) {
				dec_fail(d, ENOMEM, "cannot sort map keys");
				return;
			}
			for (uint32_t i = 1; i < n->count; i++) {
				/*
				 * Keys beyond int64_t all clamp to its ends:
				 * never valid, ignored, and not duplicates.
				 */
				if (n->child[i].key == n->child[i - 1].key &&
				    n->child[i].key != INT64_MAX &&
				    n->child[i].key != INT64_MIN) {
					dec_fail(d, EPROTO,
					    "duplicate map key");
					return;
				}
			}
		}
		if (--d->depth == 0)
			d->root_done = true;
	}
}

static void
dec_push(struct dec *d, cbl_attr *node, bool is_map, uint64_t n)
{
	struct dec_level *l;

	if ((uint64_t)d->depth + 1 > d->lim->v[CBL_LIM_MAX_DEPTH]) {
		dec_fail(d, ELOOP, "nesting exceeds max_depth");
		return;
	}
	if (n > d->lim->v[CBL_LIM_MAX_ATTRS]) {
		dec_fail(d, E2BIG, "too many attributes");
		return;
	}
	if (n > d->bodylen) {
		dec_fail(d, EBADMSG, "container larger than body");
		return;
	}
	if (d->pass == 2) {
		if (n > d->pool_size - d->pool_used) {
			dec_fail(d, EBADMSG, "inconsistent CBOR");
			return;
		}
		node->count = (uint32_t)n;
		node->child = d->pool + d->pool_used;
		d->pool_used += (uint32_t)n;
	}
	l = &d->st[d->depth++];
	l->remaining = n;
	l->is_map = is_map;
	l->want_key = is_map;
	l->node = node;
	l->next = 0;
}

static int64_t
dec_keyval(const cbl_attr *t)
{

	if (t->kind == CBL_K_UINT)
		return (t->v.u > INT64_MAX ? INT64_MAX : (int64_t)t->v.u);
	return ((t->nflags & CBL_NF_NEGBIG) != 0 ? INT64_MIN : t->v.i);
}

/* One decoded item.  "t" carries kind and value; containers carry "n". */
static void
dec_item(struct dec *d, const cbl_attr *t, uint64_t n)
{
	struct dec_level *top;
	cbl_attr *node = NULL;
	bool container = t->kind == CBL_K_NEST || t->kind == CBL_K_ARRAY;

	if (d->error != 0)
		return;
	if (d->root_done) {
		dec_fail(d, EBADMSG, "trailing data after body");
		return;
	}
	if (d->depth == 0) {
		if (t->kind != CBL_K_NEST) {
			dec_fail(d, EPROTO, "body must be a CBOR map");
			return;
		}
		if (d->pass == 2) {
			node = &d->pool[d->pool_used++];
			*node = *t;
			node->inmap = 1;
		}
		dec_push(d, node, true, n);
		dec_pop_ready(d);
		return;
	}
	top = &d->st[d->depth - 1];
	if (top->is_map && top->want_key) {
		if (t->kind != CBL_K_UINT && t->kind != CBL_K_INT) {
			dec_fail(d, EPROTO, "map keys must be integers");
			return;
		}
		top->key = dec_keyval(t);
		top->want_key = false;
		return;
	}
	if (++d->nvalues > d->lim->v[CBL_LIM_MAX_ATTRS]) {
		dec_fail(d, E2BIG, "too many attributes");
		return;
	}
	top->remaining--;
	if (top->is_map)
		top->want_key = true;
	if (d->pass == 2) {
		node = &top->node->child[top->next++];
		*node = *t;
		node->inmap = top->is_map;
		node->key = top->is_map ? top->key : 0;
	}
	if (container)
		dec_push(d, node, t->kind == CBL_K_NEST, n);
	dec_pop_ready(d);
}

static void
cb_uint(void *ctx, uint64_t v)
{
	cbl_attr t = { .kind = CBL_K_UINT, .v.u = v };

	dec_item(ctx, &t, 0);
}

static void cb_u8(void *c, uint8_t v) { cb_uint(c, v); }
static void cb_u16(void *c, uint16_t v) { cb_uint(c, v); }
static void cb_u32(void *c, uint32_t v) { cb_uint(c, v); }

static void
cb_negint(void *ctx, uint64_t raw)
{
	cbl_attr t = { .kind = CBL_K_INT };

	/* The value is -1 - raw. */
	if (raw <= (uint64_t)INT64_MAX)
		t.v.i = -1 - (int64_t)raw;
	else {
		t.nflags = CBL_NF_NEGBIG;
		t.v.u = raw;
	}
	dec_item(ctx, &t, 0);
}

static void cb_n8(void *c, uint8_t v) { cb_negint(c, v); }
static void cb_n16(void *c, uint16_t v) { cb_negint(c, v); }
static void cb_n32(void *c, uint32_t v) { cb_negint(c, v); }

static void
cb_bytes(void *ctx, cbor_data p, uint64_t len)
{
	cbl_attr t = { .kind = CBL_K_BYTES };

	t.v.s.p = p;
	t.v.s.len = (size_t)len;
	dec_item(ctx, &t, 0);
}

static void
cb_text(void *ctx, cbor_data p, uint64_t len)
{
	cbl_attr t = { .kind = CBL_K_TEXT };

	if (!cbl_utf8_valid(p, (size_t)len)) {
		dec_fail(ctx, EPROTO, "text string is not valid UTF-8");
		return;
	}
	t.v.s.p = p;
	t.v.s.len = (size_t)len;
	dec_item(ctx, &t, 0);
}

static void
cb_array(void *ctx, uint64_t n)
{
	cbl_attr t = { .kind = CBL_K_ARRAY };

	dec_item(ctx, &t, n);
}

static void
cb_map(void *ctx, uint64_t n)
{
	cbl_attr t = { .kind = CBL_K_NEST };

	dec_item(ctx, &t, n);
}

static void
cb_float(void *ctx, float v)
{
	cbl_attr t = { .kind = CBL_K_FLOAT, .v.d = v };

	dec_item(ctx, &t, 0);
}

static void
cb_double(void *ctx, double v)
{
	cbl_attr t = { .kind = CBL_K_FLOAT, .v.d = v };

	dec_item(ctx, &t, 0);
}

static void
cb_null(void *ctx)
{
	cbl_attr t = { .kind = CBL_K_NULL };

	dec_item(ctx, &t, 0);
}

static void
cb_bool(void *ctx, bool v)
{
	cbl_attr t = { .kind = CBL_K_BOOL, .v.b = v };

	dec_item(ctx, &t, 0);
}

static void
cb_indef(void *ctx)
{

	dec_fail(ctx, EPROTO, "indefinite-length items are not allowed");
}

static void
cb_tag(void *ctx, uint64_t v __unused)
{

	dec_fail(ctx, EPROTO, "CBOR tags are not allowed");
}

static void
cb_undef(void *ctx)
{

	dec_fail(ctx, EPROTO, "undefined is not allowed");
}

static const struct cbor_callbacks dec_cbs = {
	.uint8 = cb_u8,
	.uint16 = cb_u16,
	.uint32 = cb_u32,
	.uint64 = cb_uint,
	.negint8 = cb_n8,
	.negint16 = cb_n16,
	.negint32 = cb_n32,
	.negint64 = cb_negint,
	.byte_string_start = cb_indef,
	.byte_string = cb_bytes,
	.string = cb_text,
	.string_start = cb_indef,
	.indef_array_start = cb_indef,
	.array_start = cb_array,
	.indef_map_start = cb_indef,
	.map_start = cb_map,
	.tag = cb_tag,
	.float2 = cb_float,
	.float4 = cb_float,
	.float8 = cb_double,
	.undefined = cb_undef,
	.null = cb_null,
	.boolean = cb_bool,
	.indef_break = cb_indef,
};

static int
dec_run(struct dec *d, const unsigned char *p, size_t len)
{
	struct cbor_decoder_result r;
	size_t off;

	for (off = 0; !d->root_done;) {
		if (off >= len) {
			dec_fail(d, EBADMSG, "truncated CBOR body");
			break;
		}
		r = cbor_stream_decode(p + off, len - off, &dec_cbs, d);
		if (r.status == CBOR_DECODER_NEDATA) {
			dec_fail(d, EBADMSG, "truncated CBOR body");
			break;
		}
		if (r.status != CBOR_DECODER_FINISHED || r.read == 0) {
			dec_fail(d, EBADMSG, "malformed CBOR");
			break;
		}
		off += r.read;
		if (d->error != 0)
			break;
	}
	if (d->error == 0 && off != len)
		dec_fail(d, EBADMSG, "trailing data after body");
	return (d->error);
}

static void
fix_parents(cbl_attr *n)
{

	for (uint32_t i = 0; i < n->count; i++) {
		n->child[i].parent = n;
		if (n->child[i].kind == CBL_K_NEST ||
		    n->child[i].kind == CBL_K_ARRAY)
			fix_parents(&n->child[i]);
	}
}

static void
extract_fw(cbl_msg *msg)
{
	const cbl_attr *root = cbl_msg_body(msg), *a;
	char *s;

	a = cbl_map_lookup(root, CBL_FW_CODE);
	if (a != NULL && a->kind == CBL_K_UINT && a->v.u >= 1 &&
	    a->v.u <= INT_MAX)
		msg->err_code = (int)a->v.u;
	else if ((msg->hdr.flags & CBL_F_ERROR) != 0)
		msg->err_code = EPROTO;		/* ERROR without a valid code */

	a = cbl_map_lookup(root, CBL_FW_MSG);
	if (a != NULL && a->kind == CBL_K_TEXT &&
	    a->v.s.len <= CBL_ERRMSG_MAX &&
	    memchr(a->v.s.p, '\0', a->v.s.len) == NULL &&
	    (s = cbl_arena_alloc(&msg->arena, a->v.s.len + 1)) != NULL) {
		memcpy(s, a->v.s.p, a->v.s.len);
		msg->err_str = s;
	}
	a = cbl_map_lookup(root, CBL_FW_PATH);
	if (a != NULL && a->kind == CBL_K_ARRAY && a->count <= CBL_PATH_MAX)
		msg->err_path = a;
	a = cbl_map_lookup(root, CBL_FW_MISS_TYPE);
	if (a != NULL && a->kind == CBL_K_UINT && a->v.u <= CBL_ATTR_MAX)
		msg->err_miss = (int)a->v.u;
	a = cbl_map_lookup(root, CBL_FW_COOKIE);
	if (a != NULL && a->kind == CBL_K_BYTES && a->v.s.len <= CBL_COOKIE_MAX)
		msg->err_cookie = a;
}

int
cbl_msg_decode_body(cbl_msg *msg)
{
	struct dec dec = { 0 }, *d = &dec;	/* 64 levels: some 2.6 KB */
	const unsigned char *body;
	size_t bodylen;
	int error;

	body = msg->buf + msg->hdr.hdrlen;
	bodylen = msg->len - msg->hdr.hdrlen;
	if (bodylen == 0) {
		extract_fw(msg);
		return (0);
	}

	d->lim = &msg->lim;
	d->bodylen = bodylen;

	d->pass = 1;
	if ((error = dec_run(d, body, bodylen)) != 0)
		goto out;

	/* Pass 2: limits are known to hold; allocate exactly. */
	d->pool_size = d->nvalues + 1;
	d->pool = cbl_arena_alloc(&msg->arena,
	    (size_t)d->pool_size * sizeof(cbl_attr));
	if (d->pool == NULL) {
		error = ENOMEM;
		goto out;
	}
	d->pass = 2;
	d->depth = 0;
	d->root_done = false;
	d->nvalues = 0;
	if ((error = dec_run(d, body, bodylen)) != 0)
		goto out;
	msg->nodes = d->pool;
	msg->nnodes = d->pool_size;
	fix_parents(&msg->nodes[0]);
	extract_fw(msg);
out:
	if (error != 0)
		msg->errstr = d->why;
	return (error);
}

/*
 * Take ownership of "buf" (a complete frame of "len" bytes, from malloc)
 * and decode it.
 */
int
cbl_msg_from_frame(const struct cbl_limits *lim, unsigned char *buf,
    size_t len, cbl_msg **msgp)
{
	cbl_msg *msg;
	struct cbl_hdr h;
	int error;

	if ((error = cbl_hdr_decode(buf, len, lim, &h)) != 0 ||
	    h.length != len) {
		free(buf);
		return (error != 0 ? error : EMSGSIZE);
	}
	if ((error = cbl_msg_alloc_empty(lim, &msg)) != 0) {
		free(buf);
		return (error);
	}
	msg->hdr = h;
	msg->buf = buf;
	msg->len = msg->cap = len;
	msg->decoded = msg->finalized = true;
	if ((error = cbl_msg_decode_body(msg)) != 0) {
		/* Keep the header so the caller can echo it in an error. */
		*msgp = msg;
		return (error);
	}
	*msgp = msg;
	return (0);
}

int
cbl_frame_decode(cbl_ctx *ctx, const void *buf, size_t len, size_t *usedp,
    cbl_msg **msgp)
{
	struct cbl_limits lim;
	struct cbl_hdr h;
	unsigned char *copy;
	int error;

	if (ctx == NULL || msgp == NULL || (buf == NULL && len != 0))
		return (EINVAL);
	*msgp = NULL;
	if (usedp != NULL)
		*usedp = 0;
	pthread_mutex_lock(&ctx->mtx);
	lim = ctx->lim;
	pthread_mutex_unlock(&ctx->mtx);
	if ((error = cbl_hdr_decode(buf, len, &lim, &h)) != 0)
		return (error);
	if (len < h.length)
		return (EAGAIN);
	if ((copy = malloc(h.length)) == NULL)
		return (ENOMEM);
	memcpy(copy, buf, h.length);
	if (usedp != NULL)
		*usedp = h.length;
	error = cbl_msg_from_frame(&lim, copy, h.length, msgp);
	if (error != 0) {
		cbl_msg_free(*msgp);
		*msgp = NULL;
	}
	return (error);
}
