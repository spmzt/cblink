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

#define	CBLGEN_VERSION	"0.1.0"
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

/* YAML subset (docs/SPEC-FORMAT.md part 1). */
enum ytype {
	Y_SCALAR,
	Y_MAP,
	Y_SEQ,
};

struct ynode;

struct ypair {
	char		*key;
	int		 line;
	int		 col;
	struct ynode	*val;
};

struct ynode {
	enum ytype	 type;
	int		 line;
	int		 col;
	char		*str;		/* scalar */
	size_t		 len;
	bool		 quoted;
	struct ypair	*pairs;		/* map */
	size_t		 npairs;
	struct ynode	**items;	/* seq */
	size_t		 nitems;
};

#define	YAML_MAX_FILE		(1024 * 1024)
#define	YAML_MAX_LINE		4096
#define	YAML_MAX_DEPTH		32
#define	YAML_MAX_SCALAR		(64 * 1024)
#define	YAML_MAX_NODES		100000

struct ynode	*yaml_parse(const char *data, size_t len, struct diags *d);
void		 yaml_free(struct ynode *n);
const struct ynode *ymap_get(const struct ynode *map, const char *key);

#endif /* !_CBLINK_GEN_H_ */
