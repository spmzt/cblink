/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _CBL_PATTERN_H_
#define	_CBL_PATTERN_H_

/*
 * YANG patterns: XSD regular expressions (XML Schema Part 2, Appendix F,
 * as RFC 7950 section 9.4.5 says) translated to POSIX extended regular
 * expressions for regcomp(3), and matched against a whole value as XSD
 * does.  Shared by cblink-gen, which translates every pattern of a
 * schema and refuses one it cannot, and the library, which matches.
 * Values are UTF-8: matching runs in the C.UTF-8 locale, whatever the
 * program's own.
 */

#include <regex.h>
#include <stdbool.h>
#include <stddef.h>

/* The longest pattern taken, and the deepest nesting of groups. */
#define	CBL_PAT_MAX_LEN		4096
#define	CBL_PAT_MAX_DEPTH	32

/*
 * Make the C.UTF-8 locale matching uses: done by the first compile, or
 * here, before capsicum(4)'s capability mode, which newlocale(3) cannot
 * load a locale in.  -1 when there is none.
 */
int	 cbl_pattern_init(void);

/*
 * Translate an XSD regular expression to an anchored ERE ("^(...)$"),
 * malloc'd.  NULL when the pattern is not one cblink takes: why (of
 * whylen bytes) says what, and *pos where (an offset in xsd).
 */
char	*cbl_pattern_ere(const char *xsd, char *why, size_t whylen,
	    size_t *pos);

/*
 * Translate and compile.  0, or -1 with why and *pos as above (a
 * translation regcomp(3) refuses is said too).
 */
int	 cbl_pattern_compile(const char *xsd, regex_t *re, char *why,
	    size_t whylen, size_t *pos);

/* Does the value match the compiled pattern, as a whole? */
int	 cbl_pattern_compile_ere(const char *ere, regex_t *re);

bool	 cbl_pattern_match(const regex_t *re, const char *value);

void	 cbl_pattern_free(regex_t *re);

#endif /* !_CBL_PATTERN_H_ */
