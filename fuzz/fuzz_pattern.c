/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libFuzzer: a YANG pattern, as a module brings one.  What translates
 * must compile: the ERE written is one regcomp(3) reads, or the
 * translator was wrong to take the pattern.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_pattern.h"

int	LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	regex_t re;
	char *x, *ere, why[256];

	if ((x = malloc(size + 1)) == NULL)
		return (0);
	memcpy(x, data, size);
	x[size] = '\0';
	if ((ere = cbl_pattern_ere(x, why, sizeof(why), NULL)) != NULL) {
		if (cbl_pattern_compile(x, &re, why, sizeof(why), NULL) != 0)
			abort();
		(void)cbl_pattern_match(&re, x);
		cbl_pattern_free(&re);
		free(ere);
	}
	free(x);
	return (0);
}
