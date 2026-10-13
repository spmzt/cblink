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

/* Before capability mode: the modules, and the context. */
void		 yang_add_file(int fd, const char *path);
void		 yang_add_dir(const char *dir);
struct ly_ctx	*yang_ctx_new(void);

/* In capability mode: parse and compile the first module added. */
int		 yang_load(struct ly_ctx *ctx, struct diags *d, bool verbose);

#endif /* !_CBLINK_GEN_YANG_H_ */
