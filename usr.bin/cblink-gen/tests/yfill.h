/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _YFILL_H_
#define	_YFILL_H_

#include <stdbool.h>
#include <stddef.h>

struct cbl_ynode;
struct cbl_yschema;

/*
 * Node n's struct filled by the tables, in pass's way (all: every
 * optional leaf too), encoded, decoded strictly and encoded again: 0
 * when the bytes are the same, else why.
 */
int	 yround(const struct cbl_ynode *n, int pass, bool all, char *why,
	    size_t whylen);
/* The encoding of n's struct filled so, appended to b: for fuzzing. */
struct cbl_ybuf;
int	 yencoded(const struct cbl_ynode *n, int pass, bool all,
	    struct cbl_ybuf *b);
/* yround() of every node with a struct, three passes each, both ways. */
size_t	 yround_all(const struct cbl_yschema *s, size_t *nencoded, char *why,
	    size_t whylen);

#endif /* !_YFILL_H_ */
