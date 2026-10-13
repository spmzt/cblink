/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libFuzzer: a frame as it arrives from the network.  Decode it, walk
 * every attribute through the accessors, and read it as each message of
 * the control family (cblink-ctrl's rpcs' inputs and outputs, the hello
 * structure), as a notification and as a GET.  Each frame is decoded
 * twice, without and with CBL_CTX_YANG_TAGS: what the strict profile
 * accepts, the one with YANG-CBOR's tags accepts too.
 */

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "cbl_impl.h"
#include "cbl_schema.h"
#include "cbl_yctrl.h"

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
	alignas(max_align_t) char buf[512];
	const struct cbl_ymodule *ctl = cbl_yctrl_schema.mod[0];
	struct cbl_ynotif nt;
	cbl_yarena *a;
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
	if ((a = cbl_yarena_new()) == NULL)
		abort();
	for (uint32_t i = 0; i < ctl->ntop; i++)
		for (uint32_t j = 0; j < ctl->top[i]->nchild; j++) {
			const struct cbl_ynode *io = ctl->top[i]->child[j];

			if (io->kind != CBL_YN_INPUT && io->kind != CBL_YN_OUTPUT)
				continue;
			if (io->size > sizeof(buf))
				abort();
			(void)cbl_msg_ydecode(m, io, buf, a, CBL_YD_STRICT, NULL,
			    0);
		}
	(void)cbl_msg_ydecode(m, cbl_fw_node("hello"), buf, a, CBL_YD_STRICT,
	    NULL, 0);
	(void)cbl_msg_ydecode(m, cbl_fw_node("get"), buf, a, CBL_YD_STRICT,
	    NULL, 0);
	(void)cbl_msg_ynotif(m, &nt, a);
	cbl_yarena_free(a);
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
