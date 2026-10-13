/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Version 2's framework (PLAN-SDN-YANG 1.7.4): what version 1 sent under
 * negative keys is the cblink module's structures (cbl_ymod.h, generated
 * from share/yang/cblink@2026-10-13.yang), each at its SID in the body
 * like any data: an error, with RFC 8040's fields, the errno and the
 * cookie; a stream's credit; the code a stream closed or was reset with.
 *
 * What a message is told of an error and of a cookie comes in separate
 * calls and goes in one structure: kept, and written as the message is
 * encoded.  A received message's are decoded once, into its arena.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_impl.h"
#include "cbl_schema.h"
#include "cbl_ymod.h"

/* The cblink module's structure named name. */
const struct cbl_ynode *
cbl_fw_node(const char *name)
{
	const struct cbl_ymodule *m = cbl_ymod_schema.mod[0];

	for (uint32_t i = 0; i < m->ntop; i++)
		if (strcmp(m->top[i]->name, name) == 0)
			return (m->top[i]);
	return (NULL);
}

bool
cbl_fw_sid(uint64_t sid)
{
	const struct cbl_ynode *n = cbl_yschema_node(&cbl_ymod_schema, sid);

	return (n != NULL && n->kind == CBL_YN_STRUCTURE);
}

/* An error-tag identity's SID, by its name. */
static uint64_t
fw_tag(const char *name)
{

	for (uint32_t i = 0; i < cbl_ymod_schema.nident; i++)
		if (strcmp(cbl_ymod_schema.ident[i].name, name) == 0)
			return (cbl_ymod_schema.ident[i].sid);
	return (0);
}

/* What an errno says as an error-tag (RFC 8040 section 7's). */
static uint64_t
tag_of(int code, bool missing)
{
	const char *t;

	if (missing)
		return (fw_tag("missing-element"));
	switch (code) {
	case EACCES:
	case EPERM:
		t = "access-denied";
		break;
	case EEXIST:
		t = "data-exists";
		break;
	case ENOENT:
		t = "data-missing";
		break;
	case EINVAL:
	case ERANGE:
	case EDOM:
		t = "invalid-value";
		break;
	case E2BIG:
	case EMSGSIZE:
		t = "too-big";
		break;
	case EBUSY:
		t = "in-use";
		break;
	case EOPNOTSUPP:
	case ENOSYS:
	case EPROTONOSUPPORT:
		t = "operation-not-supported";
		break;
	case EAGAIN:
	case ENOMEM:
	case ENOBUFS:
		t = "resource-denied";
		break;
	case EPROTO:
	case EBADMSG:
		t = "malformed-message";
		break;
	default:
		t = "operation-failed";
		break;
	}
	return (fw_tag(t));
}

/*
 * Put.
 */

int
cbl_fw_error(cbl_msg *msg, int code, const char *text,
    const struct cbl_path_elem *path, size_t pathlen, int miss_type)
{
	struct cbl_fwout *o = &msg->fwout;
	size_t len;
	char *s;

	o->has = true;
	o->code = code;
	if (text != NULL) {
		len = strlen(text);
		if ((s = cbl_arena_alloc(&msg->arena, len + 1)) == NULL)
			return (cbl_msg_fail(msg, ENOMEM, "out of memory"));
		memcpy(s, text, len + 1);
		o->text = s;
	}
	o->npath = 0;
	o->miss = miss_type;
	if (pathlen > CBL_PATH_MAX)
		return (cbl_msg_fail(msg, EINVAL, "path too long"));
	if (pathlen > 0 || miss_type >= 0) {
		o->path = cbl_arena_alloc(&msg->arena, (pathlen + 1) *
		    sizeof(*o->path));
		if (o->path == NULL)
			return (cbl_msg_fail(msg, ENOMEM, "out of memory"));
		for (size_t i = 0; i < pathlen; i++)
			o->path[o->npath++] = path[i].v;
		/* What is missing, last: error-tag missing-element. */
		if (miss_type >= 0)
			o->path[o->npath++] = (uint64_t)miss_type;
	}
	return (0);
}

int
cbl_fw_cookie(cbl_msg *msg, const void *p, size_t len)
{
	struct cbl_fwout *o = &msg->fwout;
	void *c;

	if ((c = cbl_arena_alloc(&msg->arena, len == 0 ? 1 : len)) == NULL)
		return (cbl_msg_fail(msg, ENOMEM, "out of memory"));
	if (len > 0)
		memcpy(c, p, len);
	o->has = true;
	o->cookie = c;
	o->cookielen = len;
	return (0);
}

/* Family 1's: the node at fault by its SID alone, and the tag. */
void
cbl_fw_yerr(cbl_msg *msg, uint64_t sid, const char *tag)
{
	struct cbl_fwout *o = &msg->fwout;

	o->has = true;
	o->ysid = sid;
	o->ytag = tag;
}

/* An unsigned integer's CBOR head, into p: its length. */
static size_t
put_uint(uint8_t *p, uint64_t v)
{
	size_t n;

	if (v < 24) {
		p[0] = (uint8_t)v;
		return (1);
	}
	n = v <= UINT8_MAX ? 1 : v <= UINT16_MAX ? 2 : v <= UINT32_MAX ? 4 :
	    8;
	p[0] = (uint8_t)(n == 1 ? 0x18 : n == 2 ? 0x19 : n == 4 ? 0x1a : 0x1b);
	for (size_t i = 0; i < n; i++)
		p[1 + i] = (uint8_t)(v >> (8 * (n - 1 - i)));
	return (1 + n);
}

/* As the message is encoded: the error structure, if one was asked. */
int
cbl_fw_flush(cbl_msg *msg)
{
	struct cbl_fwout *o = &msg->fwout;
	struct cblink_error e;
	uint8_t pathbuf[(CBL_PATH_MAX + 1) * 9 + 2];
	size_t plen = 0;

	if (!o->has)
		return (0);
	o->has = false;
	memset(&e, 0, sizeof(e));
	if (o->code > 0 || o->miss >= 0 || o->ytag != NULL) {
		e.has_error_type = true;
		e.error_type = CBLINK_ERROR_ERROR_TYPE_APPLICATION;
		e.has_error_tag = true;
		e.error_tag = tag_of(o->code, o->miss >= 0);
		if (o->ytag != NULL && fw_tag(o->ytag) != 0)
			e.error_tag = fw_tag(o->ytag);
	}
	if (o->code > 0) {
		e.has_errno_ = true;
		e.errno_ = (uint32_t)o->code;
	}
	e.error_message = o->text;
	/*
	 * The path: a node's SID alone, as an instance-identifier is for
	 * one not in a list; else the array shape, [a, b, ...].
	 */
	if (o->ysid != 0) {
		plen = put_uint(pathbuf, o->ysid);
		e.error_path.p = pathbuf;
		e.error_path.len = plen;
	} else if (o->npath > 0) {
		if (o->npath < 24)
			pathbuf[plen++] = (uint8_t)(0x80 | o->npath);
		else {
			pathbuf[plen++] = 0x98;
			pathbuf[plen++] = (uint8_t)o->npath;
		}
		for (size_t i = 0; i < o->npath; i++)
			plen += put_uint(pathbuf + plen, o->path[i]);
		e.error_path.p = pathbuf;
		e.error_path.len = plen;
	}
	e.cookie.p = o->cookie;
	e.cookie.len = o->cookielen;
	if (o->cookie != NULL && o->cookielen == 0)
		e.cookie.p = "";
	return (cbl_msg_put_ynode(msg, cbl_fw_node("error"), &e));
}

int
cbl_fw_credit(cbl_msg *msg, uint32_t increment)
{
	struct cblink_credit c = { .has_increment = true,
	    .increment = increment };

	return (cbl_msg_put_ynode(msg, cbl_fw_node("credit"), &c));
}

int
cbl_fw_close(cbl_msg *msg, uint32_t code, const char *text)
{
	struct cblink_close c = { .has_code = code != 0, .code = code,
	    .message = text };

	return (cbl_msg_put_ynode(msg, cbl_fw_node("close"), &c));
}

/*
 * Read.
 */

/* The message's own arena for what is decoded of it. */
static cbl_yarena *
msg_yarena(cbl_msg *msg)
{

	if (msg->ya == NULL)
		msg->ya = cbl_yarena_new();
	return (msg->ya);
}

/* The structure name of msg's body, decoded into p; ENOENT: none. */
static int
fw_get(cbl_msg *msg, const char *name, void *p)
{
	const struct cbl_ynode *n = cbl_fw_node(name);
	cbl_yarena *a;

	if (n == NULL || (a = msg_yarena(msg)) == NULL)
		return (ENOMEM);
	return (cbl_msg_ydecode(msg, n, p, a, 0, NULL, 0));
}

/* An instance-identifier's array of unsigned integers: the path. */
static void
fw_path(cbl_msg *msg, const struct cbl_bytes *b)
{
	const uint8_t *p = b->p, *end = p + b->len;
	uint64_t n, v;
	size_t k;

	/* A SID alone: a node of family 1's. */
	if (b->len >= 1 && (*p & 0xe0) == 0) {
		n = *p & 0x1f;
		if (n < 24)
			msg->err_ysid = n;
		else if (n <= 27 && b->len == 1 + ((size_t)1 << (n - 24))) {
			for (v = 0, k = 1; k < b->len; k++)
				v = v << 8 | p[k];
			msg->err_ysid = v;
		}
		return;
	}
	if (b->len < 2 || (*p & 0xe0) != 0x80)
		return;
	if ((n = *p & 0x1f) == 24) {
		n = p[1];
		p++;
	} else if (n > 24)
		return;
	p++;
	if (n > CBL_PATH_MAX + 1)
		return;
	if ((msg->err_pathv = cbl_arena_alloc(&msg->arena, (n + 1) *
	    sizeof(*msg->err_pathv))) == NULL)
		return;
	for (k = 0; k < n; k++) {
		if (p >= end || (*p >> 5) != 0)
			return;
		v = *p & 0x1f;
		p++;
		if (v >= 24) {
			size_t len = v == 24 ? 1 : v == 25 ? 2 : v == 26 ? 4 :
			    v == 27 ? 8 : 0;

			if (len == 0 || (size_t)(end - p) < len)
				return;
			for (v = 0; len > 0; len--)
				v = v << 8 | *p++;
		}
		msg->err_pathv[k] = v;
	}
	msg->err_npath = k;
}

void
cbl_fw_extract(cbl_msg *msg)
{
	struct cblink_error e;
	struct cblink_close c;
	char *s;

	/* A stream's close: its code and message, an outcome. */
	if (fw_get(msg, "close", &c) == 0) {
		if (c.has_code && c.code <= INT32_MAX)
			msg->err_code = (int)c.code;
		if (c.message != NULL && strlen(c.message) <= CBL_ERRMSG_MAX)
			msg->err_str = c.message;
	}
	if (fw_get(msg, "error", &e) != 0) {
		/* ERROR without its structure: a protocol error. */
		if ((msg->hdr.flags & CBL_F_ERROR) != 0)
			msg->err_code = EPROTO;
		return;
	}
	if (e.has_errno_ && e.errno_ >= 1 && e.errno_ <= INT32_MAX)
		msg->err_code = (int)e.errno_;
	else if ((msg->hdr.flags & CBL_F_ERROR) != 0)
		msg->err_code = EPROTO;
	if (e.error_message != NULL &&
	    strlen(e.error_message) <= CBL_ERRMSG_MAX &&
	    (s = cbl_arena_alloc(&msg->arena, strlen(e.error_message) + 1)) !=
	    NULL) {
		memcpy(s, e.error_message, strlen(e.error_message) + 1);
		msg->err_str = s;
	}
	if (e.error_path.p != NULL)
		fw_path(msg, &e.error_path);
	/* missing-element: what is missing is the path's last. */
	if (e.has_error_tag && e.error_tag == fw_tag("missing-element") &&
	    msg->err_npath > 0 && msg->err_pathv[msg->err_npath - 1] <=
	    CBL_ATTR_MAX)
		msg->err_miss = (int)msg->err_pathv[--msg->err_npath];
	if (e.cookie.p != NULL && e.cookie.len <= CBL_COOKIE_MAX) {
		msg->err_cookiep = e.cookie.p;
		msg->err_cookielen = e.cookie.len;
		msg->has_err_cookie = true;
	}
}

uint64_t
cbl_fw_get_credit(cbl_msg *msg, bool *found)
{
	struct cblink_credit c;

	*found = fw_get(msg, "credit", &c) == 0 && c.has_increment;
	return (*found ? c.increment : 0);
}


