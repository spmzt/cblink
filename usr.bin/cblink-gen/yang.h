/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _CBLINK_GEN_YANG_H_
#define	_CBLINK_GEN_YANG_H_

/* The YANG front end, built when libyang is (CBLINK_GEN_LIBYANG). */

#define	YANG_MAX_FILE	(4 * 1024 * 1024)

struct ly_ctx;
struct diags;
struct schema;

/*
 * Before capability mode: the modules, those named (given) and those
 * found in the search directories, and the context.
 */
void		 yang_add_file(int fd, const char *path, bool given);
void		 yang_add_dir(const char *dir);
struct ly_ctx	*yang_ctx_new(const char **dirs, size_t ndirs);

/*
 * In capability mode: parse and compile the modules named, set their
 * features from yanglint-style specs (module:f1,f2; all on with none);
 * then the generator's own model of the compiled schema.
 */
int		 yang_load(struct ly_ctx *ctx, struct diags *d,
		    const char **specs, size_t nspecs);
/*
 * The module named alone, of those given, its imports from the others,
 * every feature on: what its .sid file numbers, whatever another module
 * deviates.  1: none such given.
 */
int		 yang_load_one(struct ly_ctx *ctx, struct diags *d,
		    const char *name, const char *rev);
struct schema	*yang_schema(struct ly_ctx *ctx);

#endif /* !_CBLINK_GEN_YANG_H_ */
