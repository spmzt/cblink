/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libFuzzer: a frame as it arrives from the network.  Decode it, walk
 * every attribute through the accessors, and validate and parse it as a
 * control family message.
 */

#include <stdint.h>
#include <stdlib.h>

#include "cbl_impl.h"
#include "cbl_ctrl_gen.h"

int	LLVMFuzzerInitialize(int *argc, char ***argv);
int	LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static cbl_ctx *ctx;

static void
walk(cbl_msg *m, const cbl_attr *a, int depth)
{
	const void *p;
	const char *s;
	uint64_t u;
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
	for (const cbl_attr *e = cbl_attr_first(a); e != NULL;
	    e = cbl_attr_next(e))
		walk(m, e, depth + 1);
}

int
LLVMFuzzerInitialize(int *argc __unused, char ***argv __unused)
{

	if (cbl_ctx_new(&ctx) != 0)
		abort();
	return (0);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct cbl_path_elem path[8];
	struct cbl_ctrl_ctrl c;
	struct cbl_verr ve;
	cbl_msg *m;

	if (cbl_frame_decode(ctx, data, size, NULL, &m) != 0)
		return (0);
	walk(m, cbl_msg_body(m), 0);
	(void)cbl_msg_err_code(m);
	(void)cbl_msg_err_str(m);
	(void)cbl_msg_err_path(m, path, 8);
	if (cbl_validate(cbl_msg_body(m), &cbl_ctrl_ctrl_policy, &ve) == 0)
		(void)cbl_ctrl_ctrl_parse(m, cbl_msg_body(m), &c);
	cbl_msg_free(m);
	return (0);
}
