/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libFuzzer: an XPath expression, as a subscription's filter brings one
 * from the network.  Parse it; what parses is printed, and the print
 * must parse again to the same print.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_xpath.h"

int	LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static char *
printed(const struct cbl_xp *x)
{
	char *s = NULL;
	size_t len;
	FILE *fp;

	if ((fp = open_memstream(&s, &len)) == NULL)
		abort();
	cbl_xp_print(x, fp);
	if (fclose(fp) != 0)
		abort();
	return (s);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct cbl_xp *x, *y;
	char *e, *a, *b, err[128];

	if ((e = malloc(size + 1)) == NULL)
		return (0);
	memcpy(e, data, size);
	e[size] = '\0';
	if ((x = cbl_xp_parse(e, err, sizeof(err), NULL)) != NULL) {
		a = printed(x);
		if ((y = cbl_xp_parse(a, err, sizeof(err), NULL)) == NULL)
			abort();
		b = printed(y);
		if (strcmp(a, b) != 0)
			abort();
		cbl_xp_free(y);
		free(a);
		free(b);
		cbl_xp_free(x);
	}
	free(e);
	return (0);
}
