/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * XPath 1.0 parser (cbl_xpath.h): the grammar of W3C XPath 1.0 section
 * 3, the expression tokenised first with the disambiguation rules of
 * section 3.7, then parsed by recursive descent into a tree.  The input
 * may be hostile (a subscription's filter): its length and the nesting
 * depth are bounded, and every error is an error, never a crash.
 */

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_xpath.h"

enum tok_kind {
	T_END,
	T_LPAR,
	T_RPAR,
	T_LBRA,
	T_RBRA,
	T_DOT,
	T_DOTDOT,
	T_AT,
	T_COMMA,
	T_COLONCOLON,
	T_NAMETEST,	/* prefix, s (NULL s: "*" or "prefix:*") */
	T_NODETYPE,	/* s */
	T_FUNC,		/* prefix, s */
	T_AXIS,		/* s */
	T_LITERAL,	/* s */
	T_NUMBER,	/* s, num */
	T_VAR,		/* prefix, s */
	T_OP,		/* op */
};

/* Operators, as tokens: the expression kinds, and the path ones. */
#define	OP_SLASH	1000
#define	OP_DSLASH	1001

struct tok {
	enum tok_kind	 kind;
	int		 op;		/* T_OP: enum cbl_xp_kind or OP_* */
	size_t		 pos;
	char		*prefix;
	char		*s;
	double		 num;
};

struct xp_parser {
	struct tok	*t;
	size_t		 n;
	size_t		 i;		/* next token */
	int		 depth;
	char		*err;
	size_t		 errlen;
	size_t		 errpos;
	bool		 failed;
};

static void
fail(struct xp_parser *p, size_t pos, const char *fmt, ...)
{
	va_list ap;

	if (p->failed)
		return;
	p->failed = true;
	p->errpos = pos;
	if (p->err != NULL && p->errlen > 0) {
		va_start(ap, fmt);
		vsnprintf(p->err, p->errlen, fmt, ap);
		va_end(ap);
	}
}

static char *
dupn(struct xp_parser *p, const char *s, size_t n)
{
	char *d;

	if ((d = malloc(n + 1)) == NULL) {
		fail(p, 0, "out of memory");
		return (NULL);
	}
	memcpy(d, s, n);
	d[n] = '\0';
	return (d);
}

/* XML NCName, with every byte of a multibyte character taken as a letter. */
static bool
name_start(unsigned char c)
{

	return (isalpha(c) || c == '_' || c >= 0x80);
}

static bool
name_char(unsigned char c)
{

	return (name_start(c) || isdigit(c) || c == '.' || c == '-');
}

static size_t
skip_ws(const char *e, size_t i)
{

	while (e[i] == ' ' || e[i] == '\t' || e[i] == '\n' || e[i] == '\r')
		i++;
	return (i);
}

/*
 * Section 3.7: after a token other than @, ::, (, [, a comma or an
 * operator, "*" multiplies and a name is an operator name.
 */
static bool
operator_context(const struct xp_parser *p)
{
	const struct tok *prev;

	if (p->n == 0)
		return (false);
	prev = &p->t[p->n - 1];
	return (!(prev->kind == T_AT || prev->kind == T_COLONCOLON ||
	    prev->kind == T_LPAR || prev->kind == T_LBRA ||
	    prev->kind == T_COMMA || prev->kind == T_OP));
}

static struct tok *
push(struct xp_parser *p, enum tok_kind kind, size_t pos)
{
	struct tok *t;

	if ((t = reallocarray(p->t, p->n + 1, sizeof(*t))) == NULL) {
		fail(p, pos, "out of memory");
		return (NULL);
	}
	p->t = t;
	t = &p->t[p->n++];
	memset(t, 0, sizeof(*t));
	t->kind = kind;
	t->pos = pos;
	return (t);
}

static void
lex(struct xp_parser *p, const char *e)
{
	struct tok *t;
	size_t i = 0, j, k;
	char q;

	for (;;) {
		i = skip_ws(e, i);
		if (p->failed)
			return;
		if (e[i] == '\0') {
			push(p, T_END, i);
			return;
		}
		switch (e[i]) {
		case '(':
			push(p, T_LPAR, i++);
			continue;
		case ')':
			push(p, T_RPAR, i++);
			continue;
		case '[':
			push(p, T_LBRA, i++);
			continue;
		case ']':
			push(p, T_RBRA, i++);
			continue;
		case ',':
			push(p, T_COMMA, i++);
			continue;
		case '@':
			push(p, T_AT, i++);
			continue;
		case ':':
			if (e[i + 1] != ':') {
				fail(p, i, "a ':' alone");
				return;
			}
			push(p, T_COLONCOLON, i);
			i += 2;
			continue;
		case '"':
		case '\'':
			q = e[i];
			for (j = i + 1; e[j] != '\0' && e[j] != q; j++)
				;
			if (e[j] != q) {
				fail(p, i, "an unterminated literal");
				return;
			}
			if ((t = push(p, T_LITERAL, i)) == NULL)
				return;
			t->s = dupn(p, e + i + 1, j - i - 1);
			i = j + 1;
			continue;
		case '/':
			if ((t = push(p, T_OP, i)) == NULL)
				return;
			if (e[i + 1] == '/') {
				t->op = OP_DSLASH;
				i += 2;
			} else {
				t->op = OP_SLASH;
				i++;
			}
			continue;
		case '|': case '+': case '-': case '=':
			if ((t = push(p, T_OP, i)) == NULL)
				return;
			t->op = e[i] == '|' ? CBL_XP_UNION : e[i] == '+' ?
			    CBL_XP_ADD : e[i] == '-' ? CBL_XP_SUB : CBL_XP_EQ;
			i++;
			continue;
		case '!':
			if (e[i + 1] != '=') {
				fail(p, i, "a '!' not followed by '='");
				return;
			}
			if ((t = push(p, T_OP, i)) == NULL)
				return;
			t->op = CBL_XP_NE;
			i += 2;
			continue;
		case '<':
		case '>':
			if ((t = push(p, T_OP, i)) == NULL)
				return;
			if (e[i + 1] == '=') {
				t->op = e[i] == '<' ? CBL_XP_LE : CBL_XP_GE;
				i += 2;
			} else {
				t->op = e[i] == '<' ? CBL_XP_LT : CBL_XP_GT;
				i++;
			}
			continue;
		case '*':
			if (operator_context(p)) {
				if ((t = push(p, T_OP, i)) == NULL)
					return;
				t->op = CBL_XP_MUL;
			} else if (push(p, T_NAMETEST, i) == NULL)
				return;
			i++;
			continue;
		case '$':
			if (!name_start((unsigned char)e[i + 1])) {
				fail(p, i, "a '$' not followed by a name");
				return;
			}
			if ((t = push(p, T_VAR, i)) == NULL)
				return;
			for (j = i + 1; name_char((unsigned char)e[j]); j++)
				;
			if (e[j] == ':' && name_start((unsigned char)e[j + 1])) {
				t->prefix = dupn(p, e + i + 1, j - i - 1);
				for (k = j + 1; name_char((unsigned char)e[k]); k++)
					;
				t->s = dupn(p, e + j + 1, k - j - 1);
				j = k;
			} else
				t->s = dupn(p, e + i + 1, j - i - 1);
			i = j;
			continue;
		case '.':
			if (e[i + 1] == '.') {
				push(p, T_DOTDOT, i);
				i += 2;
				continue;
			}
			if (!isdigit((unsigned char)e[i + 1])) {
				push(p, T_DOT, i++);
				continue;
			}
			break;		/* a number */
		default:
			break;
		}

		if (isdigit((unsigned char)e[i]) || e[i] == '.') {
			char *end;

			for (j = i; isdigit((unsigned char)e[j]); j++)
				;
			if (e[j] == '.')
				for (j++; isdigit((unsigned char)e[j]); j++)
					;
			if ((t = push(p, T_NUMBER, i)) == NULL)
				return;
			if ((t->s = dupn(p, e + i, j - i)) == NULL)
				return;
			t->num = strtod(t->s, &end);
			i = j;
			continue;
		}
		if (!name_start((unsigned char)e[i])) {
			fail(p, i, "an unexpected character '%c'", e[i]);
			return;
		}

		/* A name: an operator name, or what follows it decides. */
		for (j = i; name_char((unsigned char)e[j]); j++)
			;
		if (operator_context(p)) {
			static const struct {
				const char	*name;
				int		 op;
			} ops[] = {
				{ "and", CBL_XP_AND }, { "or", CBL_XP_OR },
				{ "mod", CBL_XP_MOD }, { "div", CBL_XP_DIV },
			};
			size_t m;

			for (m = 0; m < sizeof(ops) / sizeof(ops[0]); m++)
				if (strlen(ops[m].name) == j - i &&
				    strncmp(e + i, ops[m].name, j - i) == 0)
					break;
			if (m == sizeof(ops) / sizeof(ops[0])) {
				fail(p, i, "an operator expected, not '%.*s'",
				    (int)(j - i), e + i);
				return;
			}
			if ((t = push(p, T_OP, i)) == NULL)
				return;
			t->op = ops[m].op;
			i = j;
			continue;
		}
		if ((t = push(p, T_NAMETEST, i)) == NULL)
			return;
		if (e[j] == ':' && e[j + 1] == '*') {
			t->prefix = dupn(p, e + i, j - i);
			i = j + 2;
			continue;
		}
		if (e[j] == ':' && name_start((unsigned char)e[j + 1])) {
			t->prefix = dupn(p, e + i, j - i);
			for (k = j + 1; name_char((unsigned char)e[k]); k++)
				;
			t->s = dupn(p, e + j + 1, k - j - 1);
			j = k;
		} else
			t->s = dupn(p, e + i, j - i);
		i = j;
		k = skip_ws(e, i);
		if (e[k] == '(') {
			if (t->prefix == NULL && (strcmp(t->s, "node") == 0 ||
			    strcmp(t->s, "text") == 0 ||
			    strcmp(t->s, "comment") == 0 ||
			    strcmp(t->s, "processing-instruction") == 0))
				t->kind = T_NODETYPE;
			else
				t->kind = T_FUNC;
		} else if (e[k] == ':' && e[k + 1] == ':') {
			if (t->prefix != NULL) {
				fail(p, t->pos, "a prefixed axis name");
				return;
			}
			t->kind = T_AXIS;
		}
	}
}

/*
 * The parser.
 */

static struct cbl_xp	*parse_expr(struct xp_parser *);

static struct tok *
peek(struct xp_parser *p)
{

	return (&p->t[p->i]);
}

static bool
is_op(struct xp_parser *p, int op)
{

	return (peek(p)->kind == T_OP && peek(p)->op == op);
}

static bool
expect(struct xp_parser *p, enum tok_kind kind, const char *what)
{

	if (peek(p)->kind != kind) {
		fail(p, peek(p)->pos, "%s expected", what);
		return (false);
	}
	p->i++;
	return (true);
}

/* Set x's height from its children's; false, and failed, when too tall. */
static bool
heighten(struct xp_parser *p, struct cbl_xp *x)
{
	unsigned h = 0;

	for (size_t i = 0; i < x->nargs; i++)
		if (x->args[i]->height + 1 > h)
			h = x->args[i]->height + 1;
	for (size_t i = 0; i < x->npreds; i++)
		if (x->preds[i]->height + 1 > h)
			h = x->preds[i]->height + 1;
	if (x->base != NULL && x->base->height + 1 > h)
		h = x->base->height + 1;
	x->height = h;
	if (h > CBL_XP_MAX_HEIGHT) {
		fail(p, x->pos, "too many operators or steps in a row");
		return (false);
	}
	return (true);
}

static struct cbl_xp *
node(struct xp_parser *p, enum cbl_xp_kind kind, size_t pos)
{
	struct cbl_xp *x;

	if ((x = calloc(1, sizeof(*x))) == NULL) {
		fail(p, pos, "out of memory");
		return (NULL);
	}
	x->kind = kind;
	x->pos = pos;
	return (x);
}

static bool
add(struct xp_parser *p, struct cbl_xp ***v, size_t *n, struct cbl_xp *x)
{
	struct cbl_xp **nv;

	if (x == NULL)
		return (false);
	if ((nv = reallocarray(*v, *n + 1, sizeof(*nv))) == NULL) {
		cbl_xp_free(x);
		fail(p, x->pos, "out of memory");
		return (false);
	}
	*v = nv;
	(*v)[(*n)++] = x;
	return (true);
}

static char *
take(char **s)
{
	char *v = *s;

	*s = NULL;
	return (v);
}

/* Predicate*: '[' Expr ']' */
static bool
predicates(struct xp_parser *p, struct cbl_xp *x)
{

	while (!p->failed && peek(p)->kind == T_LBRA) {
		p->i++;
		if (!add(p, &x->preds, &x->npreds, parse_expr(p)))
			return (false);
		if (!expect(p, T_RBRA, "']'"))
			return (false);
	}
	return (!p->failed);
}

static bool
step_start(const struct tok *t)
{

	return (t->kind == T_NAMETEST || t->kind == T_NODETYPE ||
	    t->kind == T_AXIS || t->kind == T_AT || t->kind == T_DOT ||
	    t->kind == T_DOTDOT);
}

static struct cbl_xp *
anynode_step(struct xp_parser *p, enum cbl_xp_axis axis, size_t pos)
{
	struct cbl_xp *s;

	if ((s = node(p, CBL_XP_STEP, pos)) == NULL)
		return (NULL);
	s->axis = axis;
	s->test = CBL_XT_NODE;
	return (s);
}

static struct cbl_xp *
step(struct xp_parser *p)
{
	static const struct {
		const char	*name;
		enum cbl_xp_axis axis;
	} axes[] = {
		{ "ancestor", CBL_XA_ANCESTOR },
		{ "ancestor-or-self", CBL_XA_ANCESTOR_OR_SELF },
		{ "attribute", CBL_XA_ATTRIBUTE },
		{ "child", CBL_XA_CHILD },
		{ "descendant", CBL_XA_DESCENDANT },
		{ "descendant-or-self", CBL_XA_DESCENDANT_OR_SELF },
		{ "following", CBL_XA_FOLLOWING },
		{ "following-sibling", CBL_XA_FOLLOWING_SIBLING },
		{ "namespace", CBL_XA_NAMESPACE },
		{ "parent", CBL_XA_PARENT },
		{ "preceding", CBL_XA_PRECEDING },
		{ "preceding-sibling", CBL_XA_PRECEDING_SIBLING },
		{ "self", CBL_XA_SELF },
	};
	struct tok *t = peek(p);
	struct cbl_xp *s;
	size_t m;

	if (t->kind == T_DOT || t->kind == T_DOTDOT) {
		p->i++;
		if ((s = anynode_step(p, t->kind == T_DOT ? CBL_XA_SELF :
		    CBL_XA_PARENT, t->pos)) != NULL)
			s->abbrev = true;
		return (s);
	}
	if ((s = node(p, CBL_XP_STEP, t->pos)) == NULL)
		return (NULL);
	s->axis = CBL_XA_CHILD;
	if (t->kind == T_AT) {
		s->axis = CBL_XA_ATTRIBUTE;
		s->abbrev = true;
		p->i++;
	} else if (t->kind == T_AXIS) {
		for (m = 0; m < sizeof(axes) / sizeof(axes[0]); m++)
			if (strcmp(t->s, axes[m].name) == 0)
				break;
		if (m == sizeof(axes) / sizeof(axes[0])) {
			fail(p, t->pos, "no axis '%s'", t->s);
			goto bad;
		}
		s->axis = axes[m].axis;
		p->i++;
		if (!expect(p, T_COLONCOLON, "'::'"))
			goto bad;
	}
	t = peek(p);
	if (t->kind == T_NAMETEST) {
		s->test = t->s == NULL ? CBL_XT_ANY : CBL_XT_NAME;
		s->prefix = take(&t->prefix);
		s->s = take(&t->s);
		p->i++;
	} else if (t->kind == T_NODETYPE) {
		s->test = strcmp(t->s, "node") == 0 ? CBL_XT_NODE :
		    strcmp(t->s, "text") == 0 ? CBL_XT_TEXT :
		    strcmp(t->s, "comment") == 0 ? CBL_XT_COMMENT : CBL_XT_PI;
		p->i++;
		if (!expect(p, T_LPAR, "'('"))
			goto bad;
		if (s->test == CBL_XT_PI && peek(p)->kind == T_LITERAL) {
			s->s = take(&peek(p)->s);
			p->i++;
		}
		if (!expect(p, T_RPAR, "')'"))
			goto bad;
	} else {
		fail(p, t->pos, "a node test expected");
		goto bad;
	}
	if (!predicates(p, s) || !heighten(p, s))
		goto bad;
	return (s);
bad:
	cbl_xp_free(s);
	return (NULL);
}

/* RelativeLocationPath, its steps added to path. */
static bool
rel_path(struct xp_parser *p, struct cbl_xp *path)
{
	size_t pos;

	for (;;) {
		if (!add(p, &path->args, &path->nargs, step(p)))
			return (false);
		if (is_op(p, OP_SLASH)) {
			p->i++;
		} else if (is_op(p, OP_DSLASH)) {
			pos = peek(p)->pos;
			p->i++;
			if (!add(p, &path->args, &path->nargs,
			    anynode_step(p, CBL_XA_DESCENDANT_OR_SELF, pos)))
				return (false);
		} else
			return (true);
	}
}

static struct cbl_xp *
primary(struct xp_parser *p)
{
	struct tok *t = peek(p);
	struct cbl_xp *x;

	switch (t->kind) {
	case T_VAR:
	case T_LITERAL:
	case T_NUMBER:
		if ((x = node(p, t->kind == T_VAR ? CBL_XP_VAR : t->kind ==
		    T_LITERAL ? CBL_XP_LITERAL : CBL_XP_NUMBER, t->pos)) == NULL)
			return (NULL);
		x->prefix = take(&t->prefix);
		x->s = take(&t->s);
		x->num = t->num;
		p->i++;
		return (x);
	case T_LPAR:
		p->i++;
		x = parse_expr(p);
		if (x != NULL && !expect(p, T_RPAR, "')'")) {
			cbl_xp_free(x);
			return (NULL);
		}
		return (x);
	case T_FUNC:
		if ((x = node(p, CBL_XP_FUNC, t->pos)) == NULL)
			return (NULL);
		x->prefix = take(&t->prefix);
		x->s = take(&t->s);
		p->i++;
		if (!expect(p, T_LPAR, "'('"))
			goto bad;
		if (peek(p)->kind != T_RPAR) {
			for (;;) {
				if (!add(p, &x->args, &x->nargs, parse_expr(p)))
					goto bad;
				if (peek(p)->kind != T_COMMA)
					break;
				p->i++;
			}
		}
		if (!expect(p, T_RPAR, "')'") || !heighten(p, x))
			goto bad;
		return (x);
	bad:
		cbl_xp_free(x);
		return (NULL);
	default:
		fail(p, t->pos, t->kind == T_END ? "an expression expected, "
		    "not the end" : "an expression expected");
		return (NULL);
	}
}

/* PathExpr: a location path, or a filter followed by one. */
static struct cbl_xp *
path_expr(struct xp_parser *p)
{
	struct tok *t = peek(p);
	struct cbl_xp *x, *f, *path;
	size_t pos;

	if (is_op(p, OP_SLASH) || is_op(p, OP_DSLASH)) {
		if ((path = node(p, CBL_XP_PATH, t->pos)) == NULL)
			return (NULL);
		path->absolute = true;
		p->i++;
		if (t->op == OP_DSLASH) {
			if (!add(p, &path->args, &path->nargs,
			    anynode_step(p, CBL_XA_DESCENDANT_OR_SELF, t->pos)) ||
			    !rel_path(p, path))
				goto bad;
		} else if (step_start(peek(p)) && !rel_path(p, path))
			goto bad;
		if (!heighten(p, path))
			goto bad;
		return (path);
	}
	if (step_start(t)) {
		if ((path = node(p, CBL_XP_PATH, t->pos)) == NULL)
			return (NULL);
		if (!rel_path(p, path) || !heighten(p, path))
			goto bad;
		return (path);
	}

	if ((x = primary(p)) == NULL)
		return (NULL);
	if (peek(p)->kind == T_LBRA) {
		if ((f = node(p, CBL_XP_FILTER, x->pos)) == NULL) {
			cbl_xp_free(x);
			return (NULL);
		}
		f->args = calloc(1, sizeof(*f->args));
		if (f->args == NULL) {
			cbl_xp_free(x);
			cbl_xp_free(f);
			fail(p, 0, "out of memory");
			return (NULL);
		}
		f->args[0] = x;
		f->nargs = 1;
		x = f;
		if (!predicates(p, x) || !heighten(p, x)) {
			cbl_xp_free(x);
			return (NULL);
		}
	}
	if (!is_op(p, OP_SLASH) && !is_op(p, OP_DSLASH))
		return (x);
	if ((path = node(p, CBL_XP_PATH, x->pos)) == NULL) {
		cbl_xp_free(x);
		return (NULL);
	}
	path->base = x;
	pos = peek(p)->pos;
	if (is_op(p, OP_DSLASH) && !add(p, &path->args, &path->nargs,
	    anynode_step(p, CBL_XA_DESCENDANT_OR_SELF, pos)))
		goto bad;
	p->i++;
	if (!rel_path(p, path) || !heighten(p, path))
		goto bad;
	return (path);
bad:
	cbl_xp_free(path);
	return (NULL);
}

static struct cbl_xp *
binary(struct xp_parser *p, enum cbl_xp_kind kind, struct cbl_xp *l,
    struct cbl_xp *r, size_t pos)
{
	struct cbl_xp *x;

	if (l == NULL || r == NULL || (x = node(p, kind, pos)) == NULL)
		goto bad;
	if ((x->args = calloc(2, sizeof(*x->args))) == NULL) {
		free(x);
		fail(p, pos, "out of memory");
		goto bad;
	}
	x->args[0] = l;
	x->args[1] = r;
	x->nargs = 2;
	if (!heighten(p, x)) {
		cbl_xp_free(x);
		return (NULL);
	}
	return (x);
bad:
	cbl_xp_free(l);
	cbl_xp_free(r);
	return (NULL);
}

static struct cbl_xp *
union_expr(struct xp_parser *p)
{
	struct cbl_xp *x;
	size_t pos;

	x = path_expr(p);
	while (x != NULL && is_op(p, CBL_XP_UNION)) {
		pos = peek(p)->pos;
		p->i++;
		x = binary(p, CBL_XP_UNION, x, path_expr(p), pos);
	}
	return (x);
}

static struct cbl_xp *
unary_expr(struct xp_parser *p)
{
	struct cbl_xp *x, *n;
	size_t pos;

	if (!is_op(p, CBL_XP_SUB))
		return (union_expr(p));
	pos = peek(p)->pos;
	p->i++;
	if (++p->depth > CBL_XP_MAX_DEPTH) {
		fail(p, pos, "nested too deep");
		return (NULL);
	}
	x = unary_expr(p);
	p->depth--;
	if (x == NULL)
		return (NULL);
	if ((n = node(p, CBL_XP_NEG, pos)) == NULL ||
	    (n->args = calloc(1, sizeof(*n->args))) == NULL) {
		free(n);
		cbl_xp_free(x);
		fail(p, pos, "out of memory");
		return (NULL);
	}
	n->args[0] = x;
	n->nargs = 1;
	if (!heighten(p, n)) {
		cbl_xp_free(n);
		return (NULL);
	}
	return (n);
}

/* The binary levels, loosest first, each left-associative. */
static const int levels[][5] = {
	{ CBL_XP_OR, 0 },
	{ CBL_XP_AND, 0 },
	{ CBL_XP_EQ, CBL_XP_NE, 0 },
	{ CBL_XP_LT, CBL_XP_LE, CBL_XP_GT, CBL_XP_GE, 0 },
	{ CBL_XP_ADD, CBL_XP_SUB, 0 },
	{ CBL_XP_MUL, CBL_XP_DIV, CBL_XP_MOD, 0 },
};

static struct cbl_xp *
level(struct xp_parser *p, size_t lv)
{
	struct cbl_xp *x;
	size_t pos;
	int op;

	if (lv == sizeof(levels) / sizeof(levels[0]))
		return (unary_expr(p));
	x = level(p, lv + 1);
	for (;;) {
		if (x == NULL || peek(p)->kind != T_OP)
			return (x);
		op = 0;
		for (size_t k = 0; levels[lv][k] != 0; k++)
			if (peek(p)->op == levels[lv][k])
				op = levels[lv][k];
		if (op == 0)
			return (x);
		pos = peek(p)->pos;
		p->i++;
		x = binary(p, (enum cbl_xp_kind)op, x, level(p, lv + 1), pos);
	}
}

static struct cbl_xp *
parse_expr(struct xp_parser *p)
{
	struct cbl_xp *x;

	if (++p->depth > CBL_XP_MAX_DEPTH) {
		fail(p, peek(p)->pos, "nested too deep");
		return (NULL);
	}
	x = level(p, 0);
	p->depth--;
	return (x);
}

struct cbl_xp *
cbl_xp_parse(const char *expr, char *err, size_t errlen, size_t *errpos)
{
	struct xp_parser p = { .err = err, .errlen = errlen };
	struct cbl_xp *x = NULL;

	if (err != NULL && errlen > 0)
		err[0] = '\0';
	if (expr == NULL || strnlen(expr, CBL_XP_MAX_LEN + 1) >
	    CBL_XP_MAX_LEN)
		fail(&p, 0, "longer than %d bytes", CBL_XP_MAX_LEN);
	else
		lex(&p, expr);
	if (!p.failed) {
		x = parse_expr(&p);
		if (x != NULL && !p.failed && peek(&p)->kind != T_END)
			fail(&p, peek(&p)->pos, "unexpected text after the "
			    "expression");
	}
	for (size_t i = 0; i < p.n; i++) {
		free(p.t[i].prefix);
		free(p.t[i].s);
	}
	free(p.t);
	if (p.failed) {
		cbl_xp_free(x);
		if (errpos != NULL)
			*errpos = p.errpos;
		return (NULL);
	}
	return (x);
}

void
cbl_xp_free(struct cbl_xp *x)
{

	if (x == NULL)
		return;
	for (size_t i = 0; i < x->nargs; i++)
		cbl_xp_free(x->args[i]);
	free(x->args);
	for (size_t i = 0; i < x->npreds; i++)
		cbl_xp_free(x->preds[i]);
	free(x->preds);
	cbl_xp_free(x->base);
	free(x->prefix);
	free(x->s);
	free(x);
}

const char *
cbl_xp_axis_name(enum cbl_xp_axis axis)
{

	switch (axis) {
	case CBL_XA_CHILD:		return ("child");
	case CBL_XA_ANCESTOR:		return ("ancestor");
	case CBL_XA_ANCESTOR_OR_SELF:	return ("ancestor-or-self");
	case CBL_XA_ATTRIBUTE:		return ("attribute");
	case CBL_XA_DESCENDANT:		return ("descendant");
	case CBL_XA_DESCENDANT_OR_SELF:	return ("descendant-or-self");
	case CBL_XA_FOLLOWING:		return ("following");
	case CBL_XA_FOLLOWING_SIBLING:	return ("following-sibling");
	case CBL_XA_NAMESPACE:		return ("namespace");
	case CBL_XA_PARENT:		return ("parent");
	case CBL_XA_PRECEDING:		return ("preceding");
	case CBL_XA_PRECEDING_SIBLING:	return ("preceding-sibling");
	case CBL_XA_SELF:		return ("self");
	}
	return ("?");
}

static const char *
op_name(enum cbl_xp_kind k)
{

	switch (k) {
	case CBL_XP_OR:		return ("or");
	case CBL_XP_AND:	return ("and");
	case CBL_XP_EQ:		return ("=");
	case CBL_XP_NE:		return ("!=");
	case CBL_XP_LT:		return ("<");
	case CBL_XP_LE:		return ("<=");
	case CBL_XP_GT:		return (">");
	case CBL_XP_GE:		return (">=");
	case CBL_XP_ADD:	return ("+");
	case CBL_XP_SUB:	return ("-");
	case CBL_XP_MUL:	return ("*");
	case CBL_XP_DIV:	return ("div");
	case CBL_XP_MOD:	return ("mod");
	case CBL_XP_UNION:	return ("|");
	default:		return ("?");
	}
}

/*
 * XPath-lite (cbl_xpath.h).
 */

static const struct {
	const char	*name;
	int		 min, max;	/* arguments; max -1: any number */
	bool		 boolean;	/* returns a boolean */
} lite_funcs[] = {
	{ "bit-is-set", 2, 2, true },
	{ "boolean", 1, 1, true },
	{ "concat", 2, -1, false },
	{ "contains", 2, 2, true },
	{ "count", 1, 1, false },
	{ "current", 0, 0, false },
	{ "deref", 1, 1, false },
	{ "derived-from", 2, 2, true },
	{ "derived-from-or-self", 2, 2, true },
	{ "enum-value", 1, 1, false },
	{ "false", 0, 0, true },
	{ "normalize-space", 0, 1, false },
	{ "not", 1, 1, true },
	{ "number", 0, 1, false },
	{ "re-match", 2, 2, true },
	{ "starts-with", 2, 2, true },
	{ "string", 0, 1, false },
	{ "string-length", 0, 1, false },
	{ "substring", 2, 3, false },
	{ "substring-after", 2, 2, false },
	{ "substring-before", 2, 2, false },
	{ "translate", 3, 3, false },
	{ "true", 0, 0, true },
};

static int
lite_func(const struct cbl_xp *x)
{

	if (x->kind != CBL_XP_FUNC || x->prefix != NULL)
		return (-1);
	for (size_t i = 0; i < sizeof(lite_funcs) / sizeof(lite_funcs[0]); i++)
		if (strcmp(x->s, lite_funcs[i].name) == 0)
			return ((int)i);
	return (-1);
}

/* A predicate is a condition: a comparison, a boolean, or a path. */
static bool
condition(const struct cbl_xp *x)
{
	int f;

	switch (x->kind) {
	case CBL_XP_OR: case CBL_XP_AND:
	case CBL_XP_EQ: case CBL_XP_NE:
	case CBL_XP_LT: case CBL_XP_LE:
	case CBL_XP_GT: case CBL_XP_GE:
	case CBL_XP_PATH:
	case CBL_XP_UNION:
		return (true);
	case CBL_XP_FUNC:
		return ((f = lite_func(x)) >= 0 && lite_funcs[f].boolean);
	default:
		return (false);
	}
}

struct lite {
	char	*why;
	size_t	 whylen;
	size_t	 pos;
	bool	 refused;
};

static bool
refuse(struct lite *l, const struct cbl_xp *x, const char *fmt, ...)
{
	va_list ap;

	l->refused = true;
	l->pos = x->pos;
	if (l->why != NULL && l->whylen > 0) {
		va_start(ap, fmt);
		vsnprintf(l->why, l->whylen, fmt, ap);
		va_end(ap);
	}
	return (false);
}

static bool
lite(struct lite *l, const struct cbl_xp *x)
{
	int f;

	switch (x->kind) {
	case CBL_XP_VAR:
		return (refuse(l, x, "a variable ($%s)", x->s));
	case CBL_XP_FILTER:
		return (refuse(l, x, "a predicate on an expression"));
	case CBL_XP_FUNC:
		if ((f = lite_func(x)) < 0)
			return (refuse(l, x, "the function %s%s%s()",
			    x->prefix != NULL ? x->prefix : "",
			    x->prefix != NULL ? ":" : "", x->s));
		if ((int)x->nargs < lite_funcs[f].min ||
		    (lite_funcs[f].max >= 0 && (int)x->nargs >
		    lite_funcs[f].max))
			return (refuse(l, x, "%s() with %zu arguments", x->s,
			    x->nargs));
		break;
	case CBL_XP_PATH:
		if (x->base != NULL && (x->base->kind != CBL_XP_FUNC ||
		    x->base->prefix != NULL ||
		    (strcmp(x->base->s, "current") != 0 &&
		    strcmp(x->base->s, "deref") != 0)))
			return (refuse(l, x->base, "a path from an expression "
			    "other than current() or deref()"));
		if (x->base != NULL && !lite(l, x->base))
			return (false);
		break;
	case CBL_XP_STEP:
		if (x->axis != CBL_XA_CHILD && x->axis != CBL_XA_PARENT &&
		    x->axis != CBL_XA_SELF &&
		    x->axis != CBL_XA_DESCENDANT_OR_SELF)
			return (refuse(l, x, "the axis %s",
			    cbl_xp_axis_name(x->axis)));
		if (x->test != CBL_XT_NAME && x->test != CBL_XT_ANY &&
		    x->test != CBL_XT_NODE)
			return (refuse(l, x, "a node test other than a name, "
			    "* or node()"));
		for (size_t i = 0; i < x->npreds; i++)
			if (!condition(x->preds[i]))
				return (refuse(l, x->preds[i], "a predicate "
				    "that is not a condition (a position?)"));
		break;
	default:
		break;
	}
	for (size_t i = 0; i < x->nargs; i++)
		if (!lite(l, x->args[i]))
			return (false);
	for (size_t i = 0; i < x->npreds; i++)
		if (!lite(l, x->preds[i]))
			return (false);
	return (true);
}

bool
cbl_xp_lite(const struct cbl_xp *x, char *why, size_t whylen, size_t *pos)
{
	struct lite l = { .why = why, .whylen = whylen };

	if (why != NULL && whylen > 0)
		why[0] = '\0';
	if (lite(&l, x))
		return (true);
	if (pos != NULL)
		*pos = l.pos;
	return (false);
}

/*
 * Printing: parentheses only where precedence needs them, so that the
 * print never nests deeper than the expression it came from.  The
 * levels, loosest first: or, and, equality, relational, additive,
 * multiplicative, unary minus, union, then paths, and primaries above
 * them.
 */
static int
prec(const struct cbl_xp *x)
{

	switch (x->kind) {
	case CBL_XP_OR:		return (1);
	case CBL_XP_AND:	return (2);
	case CBL_XP_EQ:
	case CBL_XP_NE:		return (3);
	case CBL_XP_LT:
	case CBL_XP_LE:
	case CBL_XP_GT:
	case CBL_XP_GE:		return (4);
	case CBL_XP_ADD:
	case CBL_XP_SUB:	return (5);
	case CBL_XP_MUL:
	case CBL_XP_DIV:
	case CBL_XP_MOD:	return (6);
	case CBL_XP_NEG:	return (7);
	case CBL_XP_UNION:	return (8);
	case CBL_XP_PATH:
	case CBL_XP_STEP:	return (9);
	default:		return (10);	/* primaries, filters */
	}
}

static void	print_at(const struct cbl_xp *, int, FILE *);

static void
print_preds(const struct cbl_xp *x, FILE *fp)
{

	for (size_t i = 0; i < x->npreds; i++) {
		fputc('[', fp);
		print_at(x->preds[i], 0, fp);
		fputc(']', fp);
	}
}

void
cbl_xp_print(const struct cbl_xp *x, FILE *fp)
{

	print_at(x, 0, fp);
}

/* x where an operand binding at least as tightly as min belongs. */
static void
print_at(const struct cbl_xp *x, int min, FILE *fp)
{
	bool paren = prec(x) < min;

	if (paren)
		fputc('(', fp);
	switch (x->kind) {
	case CBL_XP_NEG:
		fputc('-', fp);
		print_at(x->args[0], prec(x), fp);
		break;
	case CBL_XP_LITERAL:
		if (strchr(x->s, '\'') != NULL)
			fprintf(fp, "\"%s\"", x->s);
		else
			fprintf(fp, "'%s'", x->s);
		break;
	case CBL_XP_NUMBER:
		fputs(x->s, fp);
		break;
	case CBL_XP_VAR:
		fprintf(fp, "$%s%s%s", x->prefix != NULL ? x->prefix : "",
		    x->prefix != NULL ? ":" : "", x->s);
		break;
	case CBL_XP_FUNC:
		fprintf(fp, "%s%s%s(", x->prefix != NULL ? x->prefix : "",
		    x->prefix != NULL ? ":" : "", x->s);
		for (size_t i = 0; i < x->nargs; i++) {
			if (i > 0)
				fputs(", ", fp);
			print_at(x->args[i], 0, fp);
		}
		fputc(')', fp);
		break;
	case CBL_XP_FILTER:
		/* A primary only: anything else in parentheses. */
		print_at(x->args[0], 10, fp);
		print_preds(x, fp);
		break;
	case CBL_XP_PATH:
		if (x->base != NULL)
			print_at(x->base, 10, fp);
		if (x->absolute && x->nargs == 0)
			fputc('/', fp);
		for (size_t i = 0; i < x->nargs; i++) {
			if (i > 0 || x->absolute || x->base != NULL)
				fputc('/', fp);
			print_at(x->args[i], 0, fp);
		}
		break;
	case CBL_XP_STEP:
		fprintf(fp, "%s::", cbl_xp_axis_name(x->axis));
		switch (x->test) {
		case CBL_XT_NAME:
			fprintf(fp, "%s%s%s", x->prefix != NULL ? x->prefix :
			    "", x->prefix != NULL ? ":" : "", x->s);
			break;
		case CBL_XT_ANY:
			fprintf(fp, "%s%s*", x->prefix != NULL ? x->prefix :
			    "", x->prefix != NULL ? ":" : "");
			break;
		case CBL_XT_NODE:
			fputs("node()", fp);
			break;
		case CBL_XT_TEXT:
			fputs("text()", fp);
			break;
		case CBL_XT_COMMENT:
			fputs("comment()", fp);
			break;
		case CBL_XT_PI:
			fputs("processing-instruction(", fp);
			if (x->s != NULL)
				fprintf(fp, "'%s'", x->s);
			fputc(')', fp);
			break;
		}
		print_preds(x, fp);
		break;
	default:
		/* Left-associative: the right operand one level tighter. */
		print_at(x->args[0], prec(x), fp);
		fprintf(fp, " %s ", op_name(x->kind));
		print_at(x->args[1], prec(x) + 1, fp);
		break;
	}
	if (paren)
		fputc(')', fp);
}
