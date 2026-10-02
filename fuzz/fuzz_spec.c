/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* libFuzzer: a family spec, through the YAML parser and spec_load(). */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "gen.h"
#include "spec.h"

int	LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct diags d = { .file = "fuzz.yaml" };
	struct ynode *root;
	struct spec *s;
	char *buf;

	/* As cblink-gen: at most YAML_MAX_FILE bytes, NUL-terminated. */
	if (size > YAML_MAX_FILE || (buf = malloc(size + 1)) == NULL)
		return (0);
	memcpy(buf, data, size);
	buf[size] = '\0';
	if ((root = yaml_parse(buf, size, &d)) != NULL) {
		if ((s = spec_load(root, d.file, false, &d)) != NULL)
			spec_free(s);
		yaml_free(root);
	}
	diag_free(&d);
	free(buf);
	return (0);
}
