/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libFuzzer: a frame as it arrives from the network.  Decode it, walk
 * the tree the decoder made, look its top-level items up by SID, and
 * read it as each message of the control family (cblink-ctrl's rpcs'
 * inputs and outputs, the hello structure), as a notification and as a
 * GET; and say what its error was.
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

static cbl_ctx *ctx;

/* The decoder's tree: a tag is YANG-CBOR's or none. */
static void
walk(const cbl_attr *a, int depth)
{

	if (a == NULL || depth > 64)
		return;
	if (a->tag != 0 && a->tag != 4 && (a->tag < 43 || a->tag > 47))
		abort();
	if (a->kind == CBL_K_NEST || a->kind == CBL_K_ARRAY)
		for (uint32_t i = 0; i < a->count; i++)
			walk(&a->child[i], depth + 1);
}

int
LLVMFuzzerInitialize(int *argc __unused, char ***argv __unused)
{

	if (cbl_ctx_new(&ctx) != 0)
		abort();
	return (0);
}

static int
one(cbl_ctx *c, const uint8_t *data, size_t size)
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

	if ((error = cbl_frame_decode(c, data, size, NULL, &m)) != 0)
		return (error);
	walk(m->nodes, 0);
	for (uint32_t i = 0; m->nodes != NULL && i < m->nodes->count; i++) {
		const cbl_attr *it = &m->nodes->child[i];
		const void *p;
		size_t len;

		/* Keys beyond 2^63 - 1 clamp to it, and may be several. */
		if (it->key >= 1 && it->key < INT64_MAX &&
		    (cbl_msg_sid_raw(m, (uint64_t)it->key,
		    &p, &len) != 0 || p != m->buf + m->hdr.hdrlen + it->off ||
		    len != it->len))
			abort();
	}
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

	(void)one(ctx, data, size);
	return (0);
}
