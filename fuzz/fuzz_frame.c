/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libFuzzer: a frame as it arrives from the network.  Decode it, walk
 * every attribute through the accessors, and validate and parse it as a
 * control family message.  Each frame is decoded twice, without and with
 * CBL_CTX_YANG_TAGS: what the strict profile accepts, the one with
 * YANG-CBOR's tags accepts too.
 */

#include <stdint.h>
#include <stdlib.h>

#include "cbl_impl.h"
#include "cbl_ctrl_gen.h"

int	LLVMFuzzerInitialize(int *argc, char ***argv);
int	LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static cbl_ctx *ctx, *yctx;

static void
walk(cbl_msg *m, const cbl_attr *a, int depth)
{
	const void *p;
	const char *s;
	uint64_t u, tag;
	int64_t i;
	double d;
	size_t len;
	bool b;

	if (a == NULL || depth > 64)
		return;
	(void)cbl_attr_uint(a, &u);
	(void)cbl_attr_int(a, &i);
	(void)cbl_attr_bool(a, &b);
	(void)cbl_attr_double(a, &d);
	(void)cbl_attr_bytes(a, &p, &len);
	(void)cbl_attr_str(m, a, &s);
	if (cbl_attr_tag(a, &tag) == 0 && tag != 4 && (tag < 43 || tag > 47))
		abort();
	for (const cbl_attr *e = cbl_attr_first(a); e != NULL;
	    e = cbl_attr_next(e))
		walk(m, e, depth + 1);
}

int
LLVMFuzzerInitialize(int *argc __unused, char ***argv __unused)
{

	if (cbl_ctx_new(&ctx) != 0 || cbl_ctx_new(&yctx) != 0 ||
	    cbl_ctx_set_flags(yctx, CBL_CTX_YANG_TAGS) != 0)
		abort();
	return (0);
}

static int
one(cbl_ctx *c0, const uint8_t *data, size_t size)
{
	struct cbl_path_elem path[8];
	struct cbl_ctrl_ctrl c;
	struct cbl_verr ve;
	const void *ck;
	size_t cklen;
	cbl_msg *m;
	int error;

	if ((error = cbl_frame_decode(c0, data, size, NULL, &m)) != 0)
		return (error);
	walk(m, cbl_msg_body(m), 0);
	(void)cbl_msg_err_code(m);
	(void)cbl_msg_err_str(m);
	(void)cbl_msg_err_path(m, path, 8);
	(void)cbl_msg_err_miss_type(m);
	(void)cbl_msg_err_cookie(m, &ck, &cklen);
	if (cbl_validate(cbl_msg_body(m), &cbl_ctrl_ctrl_policy, &ve) == 0)
		(void)cbl_ctrl_ctrl_parse(m, cbl_msg_body(m), &c);
	cbl_msg_free(m);
	return (0);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{

	if (one(ctx, data, size) == 0 && one(yctx, data, size) != 0)
		abort();
	return (0);
}
