/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _CBLINK_GEN_H_
#define	_CBLINK_GEN_H_

#include <sys/param.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	CBLGEN_VERSION	"0.2.0"
/* The libcblink major version the generated code is written for. */
#define	CBLGEN_LIB_MAJOR	0

/* Growable string buffer. */
struct buf {
	char	*p;
	size_t	 len;
	size_t	 cap;
};

void	buf_init(struct buf *b);
void	buf_free(struct buf *b);
void	buf_add(struct buf *b, const char *s, size_t len);
void	buf_puts(struct buf *b, const char *s);
void	buf_printf(struct buf *b, const char *fmt, ...) __printflike(2, 3);
void	buf_vprintf(struct buf *b, const char *fmt, va_list ap)
	    __printflike(2, 0);
char	*xstrdup(const char *s);
char	*xasprintf(const char *fmt, ...) __printflike(1, 2);
char	*xstrndup(const char *s, size_t len);
void	*xcalloc(size_t n, size_t size);
void	*xreallocarray(void *p, size_t n, size_t size);
int	 write_file(int dirfd, const char *name, const struct buf *b);

/* Diagnostics: "file:line:col: error: msg". */
struct diag {
	int	 line;
	int	 col;
	char	*msg;
};

struct diags {
	const char	*file;
	struct diag	*v;
	size_t		 n;
	size_t		 cap;
};

#define	DIAG_MAX	50

void	diag_add(struct diags *d, int line, int col, const char *fmt, ...)
	    __printflike(4, 5);
void	diag_print(struct diags *d);
void	diag_free(struct diags *d);

/* The largest file read: a .sid file. */
#define	MAX_FILE	(16 * 1024 * 1024)

#endif /* !_CBLINK_GEN_H_ */
