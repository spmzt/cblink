/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _CBL_XPATH_H_
#define	_CBL_XPATH_H_

/*
 * XPath 1.0 expressions (W3C XPath 1.0, as YANG uses them in when, must,
 * path and filters, RFC 7950 section 6.4), parsed into a tree.  Shared
 * by cblink-gen and the library; the subset cblink evaluates
 * ("XPath-lite") is checked on the tree, not by the parser, which takes
 * the whole grammar.  The parser needs nothing but libc.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

enum cbl_xp_kind {
	CBL_XP_OR = 1,		/* args: left, right */
	CBL_XP_AND,
	CBL_XP_EQ,
	CBL_XP_NE,
	CBL_XP_LT,
	CBL_XP_LE,
	CBL_XP_GT,
	CBL_XP_GE,
	CBL_XP_ADD,
	CBL_XP_SUB,
	CBL_XP_MUL,
	CBL_XP_DIV,
	CBL_XP_MOD,
	CBL_XP_UNION,
	CBL_XP_NEG,		/* args: the operand */
	CBL_XP_LITERAL,		/* s */
	CBL_XP_NUMBER,		/* num, and s as written */
	CBL_XP_VAR,		/* prefix, s: $prefix:s */
	CBL_XP_FUNC,		/* prefix, s; args: the arguments */
	CBL_XP_FILTER,		/* args[0]: primary; preds */
	CBL_XP_PATH,		/* absolute; args: steps, after base if any */
	CBL_XP_STEP,		/* axis, test, prefix, s; preds */
};

enum cbl_xp_axis {
	CBL_XA_CHILD,
	CBL_XA_ANCESTOR,
	CBL_XA_ANCESTOR_OR_SELF,
	CBL_XA_ATTRIBUTE,
	CBL_XA_DESCENDANT,
	CBL_XA_DESCENDANT_OR_SELF,
	CBL_XA_FOLLOWING,
	CBL_XA_FOLLOWING_SIBLING,
	CBL_XA_NAMESPACE,
	CBL_XA_PARENT,
	CBL_XA_PRECEDING,
	CBL_XA_PRECEDING_SIBLING,
	CBL_XA_SELF,
};

enum cbl_xp_test {
	CBL_XT_NAME,		/* prefix (or NULL) and s */
	CBL_XT_ANY,		/* *, or prefix:* */
	CBL_XT_NODE,		/* node() */
	CBL_XT_TEXT,		/* text() */
	CBL_XT_COMMENT,		/* comment() */
	CBL_XT_PI,		/* processing-instruction(), s the literal */
};

struct cbl_xp {
	enum cbl_xp_kind kind;
	size_t		 pos;		/* offset in the expression */
	struct cbl_xp	**args;
	size_t		 nargs;
	struct cbl_xp	**preds;	/* step, filter: predicates */
	size_t		 npreds;
	struct cbl_xp	*base;		/* path: a filter it starts from */
	char		*prefix;
	char		*s;
	double		 num;
	enum cbl_xp_axis axis;
	enum cbl_xp_test test;
	bool		 absolute;	/* path: starts with / or // */
	bool		 abbrev;	/* step: written as . or .. or @x */
	unsigned	 height;	/* 0 for a leaf, else 1 + its tallest */
};

/*
 * Bounds against hostile input: nesting depth, length, and the tree's
 * height, which a long chain of operators makes tall without nesting
 * (whatever walks the tree recurses).
 */
#define	CBL_XP_MAX_DEPTH	64
#define	CBL_XP_MAX_LEN		65536
#define	CBL_XP_MAX_HEIGHT	256

/*
 * Parse expr.  On error, NULL, and err (of errlen bytes) says why and
 * *errpos where (an offset in expr).
 */
struct cbl_xp	*cbl_xp_parse(const char *expr, char *err, size_t errlen,
		    size_t *errpos);
void		 cbl_xp_free(struct cbl_xp *x);

/*
 * Print the tree as an expression, every step with its axis and
 * parentheses only where precedence needs them: parsing the output
 * again prints the same, and nests no deeper than what was parsed.
 */
void		 cbl_xp_print(const struct cbl_xp *x, FILE *fp);

const char	*cbl_xp_axis_name(enum cbl_xp_axis axis);

/*
 * Is the tree within XPath-lite, what cblink evaluates?  The axes child,
 * parent, self and descendant-or-self; name tests, "*" and node(); the
 * functions current(), deref(), derived-from(), derived-from-or-self(),
 * enum-value(), bit-is-set(), re-match(), count(), not(), true(),
 * false(), boolean(), number() and the string functions, each with its
 * number of arguments; paths from current() or deref() only; predicates
 * that are conditions, never positions; no variables.  On refusal,
 * false, why (of whylen bytes) and *pos, the offset of the construct.
 */
bool		 cbl_xp_lite(const struct cbl_xp *x, char *why, size_t whylen,
		    size_t *pos);

#endif /* !_CBL_XPATH_H_ */
