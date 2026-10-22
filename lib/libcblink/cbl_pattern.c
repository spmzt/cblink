/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * XSD regular expressions to POSIX EREs (cbl_pattern.h).
 *
 * XSD's grammar (XML Schema Part 2, Appendix F) is parsed by recursive
 * descent and written out as an ERE that regcomp(3) reads the same way:
 *
 * - a pattern matches the whole value: the ERE is "^(...)$", and XSD's
 *   "^" and "$", ordinary characters there, are escaped;
 * - "." is any character but a newline or a carriage return;
 * - a character class is rebuilt as a POSIX bracket expression, which
 *   has no escapes: "]" first, "-" last, "^" never first, "[" where it
 *   cannot open "[:", "[." or "[=";
 * - \n, \r and \t become those characters; \s is space, tab, newline
 *   and carriage return, as XSD says;
 * - \d and \p{Nd} are [:digit:], \p{L} [:alpha:], \p{Lu} [:upper:],
 *   \p{Ll} [:lower:]: in C.UTF-8 these are FreeBSD's Unicode classes,
 *   which hold what the categories hold.  \p{N} is [:digit:] too, and so
 *   narrower: the numbers that are not digits (², Ⅻ) are not in it.
 *   \w is the letters and digits and the ASCII symbols ($ + < = > ^ ` |
 *   ~): XSD's \w also holds the other symbols and the marks, which no
 *   POSIX class gives.  \i is the letters, "_" and ":", \c those, the
 *   digits, "." and "-".  Their complements (\D, \S, \W, \I, \C, \P{})
 *   are negated brackets, so cannot sit inside another bracket.
 *
 * Refused, with the reason: what is not XSD (back-references and every
 * escape XSD has not), character class subtraction, the categories and
 * blocks no POSIX class matches, a complement inside a class, counts
 * over RE_DUP_MAX, text that is not UTF-8.
 */

#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xlocale.h>

#include "cbl_pattern.h"

struct pbuf {
	char	*p;
	size_t	 len;
	size_t	 cap;
};

/* A bracket expression being gathered. */
struct pmember {
	uint32_t	 lo, hi;	/* a character, or a range */
};

struct pclass {
	struct pmember	*m;
	size_t		 n;
	const char	*named[8];	/* "[:alpha:]" and the like */
	size_t		 nnamed;
	bool		 neg;
};

struct pparse {
	const char	*s;
	size_t		 i;
	int		 depth;
	struct pbuf	 out;
	char		*why;
	size_t		 whylen;
	size_t		 pos;
	bool		 failed;
};

static bool	regexp(struct pparse *);

static bool
refuse(struct pparse *p, size_t pos, const char *fmt, ...)
{
	va_list ap;

	if (p->failed)
		return (false);
	p->failed = true;
	p->pos = pos;
	if (p->why != NULL && p->whylen > 0) {
		va_start(ap, fmt);
		vsnprintf(p->why, p->whylen, fmt, ap);
		va_end(ap);
	}
	return (false);
}

static bool
put(struct pparse *p, const char *s, size_t n)
{
	char *np;
	size_t cap;

	if (p->out.len + n + 1 > p->out.cap) {
		cap = p->out.cap == 0 ? 64 : p->out.cap;
		while (cap < p->out.len + n + 1)
			cap *= 2;
		if ((np = realloc(p->out.p, cap)) == NULL)
			return (refuse(p, p->i, "out of memory"));
		p->out.p = np;
		p->out.cap = cap;
	}
	memcpy(p->out.p + p->out.len, s, n);
	p->out.len += n;
	p->out.p[p->out.len] = '\0';
	return (true);
}

static bool
puts_(struct pparse *p, const char *s)
{

	return (put(p, s, strlen(s)));
}

/* One UTF-8 character at s[*i]: its code point, *i past it. */
static bool
utf8(struct pparse *p, size_t *i, uint32_t *cp)
{
	const unsigned char *s = (const unsigned char *)p->s + *i;
	uint32_t c;
	int n;

	if (s[0] < 0x80) {
		*cp = s[0];
		(*i)++;
		return (true);
	}
	if (s[0] >= 0xc2 && s[0] <= 0xdf) {
		n = 1;
		c = s[0] & 0x1f;
	} else if (s[0] >= 0xe0 && s[0] <= 0xef) {
		n = 2;
		c = s[0] & 0x0f;
	} else if (s[0] >= 0xf0 && s[0] <= 0xf4) {
		n = 3;
		c = s[0] & 0x07;
	} else
		return (refuse(p, *i, "not UTF-8"));
	for (int k = 1; k <= n; k++) {
		if ((s[k] & 0xc0) != 0x80)
			return (refuse(p, *i, "not UTF-8"));
		c = (c << 6) | (s[k] & 0x3f);
	}
	if ((n == 2 && c < 0x800) || (n == 3 && (c < 0x10000 ||
	    c > 0x10ffff)) || (c >= 0xd800 && c <= 0xdfff))
		return (refuse(p, *i, "not UTF-8"));
	*cp = c;
	*i += (size_t)n + 1;
	return (true);
}

static bool
put_cp(struct pparse *p, uint32_t c)
{
	char b[4];

	if (c < 0x80) {
		b[0] = (char)c;
		return (put(p, b, 1));
	}
	if (c < 0x800) {
		b[0] = (char)(0xc0 | (c >> 6));
		b[1] = (char)(0x80 | (c & 0x3f));
		return (put(p, b, 2));
	}
	if (c < 0x10000) {
		b[0] = (char)(0xe0 | (c >> 12));
		b[1] = (char)(0x80 | ((c >> 6) & 0x3f));
		b[2] = (char)(0x80 | (c & 0x3f));
		return (put(p, b, 3));
	}
	b[0] = (char)(0xf0 | (c >> 18));
	b[1] = (char)(0x80 | ((c >> 12) & 0x3f));
	b[2] = (char)(0x80 | ((c >> 6) & 0x3f));
	b[3] = (char)(0x80 | (c & 0x3f));
	return (put(p, b, 4));
}

/*
 * Bracket expressions.
 */

static bool
add_range(struct pparse *p, struct pclass *c, uint32_t lo, uint32_t hi)
{
	struct pmember *nm;

	if ((nm = reallocarray(c->m, c->n + 1, sizeof(*nm))) == NULL)
		return (refuse(p, p->i, "out of memory"));
	c->m = nm;
	c->m[c->n].lo = lo;
	c->m[c->n++].hi = hi;
	return (true);
}

static bool
add_named(struct pparse *p, struct pclass *c, const char *name)
{

	for (size_t k = 0; k < c->nnamed; k++)
		if (strcmp(c->named[k], name) == 0)
			return (true);
	if (c->nnamed == sizeof(c->named) / sizeof(c->named[0]))
		return (refuse(p, p->i, "too many classes in one bracket"));
	c->named[c->nnamed++] = name;
	return (true);
}

static bool
add_chars(struct pparse *p, struct pclass *c, const char *chars)
{

	for (; *chars != '\0'; chars++)
		if (!add_range(p, c, (unsigned char)*chars,
		    (unsigned char)*chars))
			return (false);
	return (true);
}

/* Characters a bracket expression treats specially. */
static bool
special(uint32_t c)
{

	return (c == ']' || c == '[' || c == '^' || c == '-');
}

/*
 * Write a gathered class.  A range with a special character at an end
 * is written out character by character, all being ASCII then.
 */
static bool
put_class(struct pparse *p, struct pclass *c)
{
	bool close = false, open = false, caret = false, dash = false;
	bool other;

	for (size_t k = 0; k < c->n; k++)
		if (c->m[k].lo != c->m[k].hi && (special(c->m[k].lo) ||
		    special(c->m[k].hi))) {
			uint32_t lo = c->m[k].lo, hi = c->m[k].hi;

			if (hi > 0x7f)
				return (refuse(p, p->i, "a range from a "
				    "bracket's special character past ASCII"));
			c->m[k].hi = lo;
			for (uint32_t ch = lo + 1; ch <= hi; ch++)
				if (!add_range(p, c, ch, ch))
					return (false);
		}
	other = c->nnamed > 0;
	for (size_t k = 0; k < c->n; k++) {
		uint32_t lo = c->m[k].lo;

		if (lo != c->m[k].hi || !special(lo))
			other = true;
		else {
			close |= lo == ']';
			open |= lo == '[';
			caret |= lo == '^';
			dash |= lo == '-';
		}
	}
	/*
	 * Nothing but "^" (and "-"): "^" may not be first.  "^" alone is
	 * that character; with "-", "-" goes first.
	 */
	if (!c->neg && caret && !other && !close && !open)
		return (puts_(p, dash ? "[-^]" : "\\^"));
	if (!puts_(p, c->neg ? "[^" : "[") || (close && !puts_(p, "]")))
		return (false);
	for (size_t k = 0; k < c->nnamed; k++)
		if (!puts_(p, c->named[k]))
			return (false);
	for (size_t k = 0; k < c->n; k++) {
		uint32_t lo = c->m[k].lo, hi = c->m[k].hi;

		if (lo == hi && special(lo))
			continue;
		if (!put_cp(p, lo))
			return (false);
		if (lo != hi && (!puts_(p, "-") || !put_cp(p, hi)))
			return (false);
	}
	/*
	 * Then "[", "^" and "-", in that order: "[" is followed by "^",
	 * "-" or the closing "]", never by ":", "." or "=", and "^" is not
	 * first, something having come before it.
	 */
	if ((open && !puts_(p, "[")) || (caret && !puts_(p, "^")) ||
	    (dash && !puts_(p, "-")))
		return (false);
	return (puts_(p, "]"));
}

/*
 * Escapes.  A multi-character one adds its members to c; a complemented
 * one (\D and the like) is refused inside a class, and outside one is
 * written as a negated bracket by the caller (neg set).
 */
enum esc { E_CHAR, E_CLASS, E_FAIL };

static bool
category(struct pparse *p, struct pclass *c, size_t at)
{
	static const struct {
		const char	*cat;
		const char	*named;
	} cats[] = {
		{ "L", "[:alpha:]" }, { "Lu", "[:upper:]" },
		{ "Ll", "[:lower:]" }, { "N", "[:digit:]" },
		{ "Nd", "[:digit:]" },
	};
	const char *s = p->s + p->i, *e;
	size_t len;

	if (s[0] != '{' || (e = strchr(s, '}')) == NULL)
		return (refuse(p, at, "\\p or \\P without {category}"));
	len = (size_t)(e - s - 1);
	p->i += len + 2;
	for (size_t k = 0; k < sizeof(cats) / sizeof(cats[0]); k++)
		if (strlen(cats[k].cat) == len && strncmp(s + 1, cats[k].cat,
		    len) == 0)
			return (add_named(p, c, cats[k].named));
	if (len > 2 && strncmp(s + 1, "Is", 2) == 0)
		return (refuse(p, at, "the block escape \\p{%.*s}: no POSIX "
		    "class matches a Unicode block", (int)len, s + 1));
	return (refuse(p, at, "the category \\p{%.*s}: no POSIX class "
	    "matches it", (int)len, s + 1));
}

static enum esc
escape(struct pparse *p, struct pclass *c, bool *neg, uint32_t *ch)
{
	size_t at = p->i;
	char e;

	p->i++;			/* the backslash */
	e = p->s[p->i];
	if (e == '\0') {
		refuse(p, at, "a backslash at the end");
		return (E_FAIL);
	}
	p->i++;
	*neg = false;
	switch (e) {
	case 'n':
		*ch = '\n';
		return (E_CHAR);
	case 'r':
		*ch = '\r';
		return (E_CHAR);
	case 't':
		*ch = '\t';
		return (E_CHAR);
	case '\\': case '|': case '.': case '?': case '*': case '+':
	case '(': case ')': case '{': case '}': case '-': case '[':
	case ']': case '^':
		*ch = (unsigned char)e;
		return (E_CHAR);
	case 'D': case 'S': case 'W': case 'I': case 'C': case 'P':
		*neg = true;
		/* FALLTHROUGH */
	case 'd': case 's': case 'w': case 'i': case 'c': case 'p':
		break;
	default:
		refuse(p, at, "\\%c is not an XSD escape%s", e, e >= '1' &&
		    e <= '9' ? " (no back-references in XSD)" : "");
		return (E_FAIL);
	}
	switch (e) {
	case 'd': case 'D':
		if (!add_named(p, c, "[:digit:]"))
			return (E_FAIL);
		break;
	case 's': case 'S':
		if (!add_chars(p, c, " \t\n\r"))
			return (E_FAIL);
		break;
	case 'w': case 'W':
		if (!add_named(p, c, "[:alnum:]") || !add_chars(p, c,
		    "$+<=>^`|~"))
			return (E_FAIL);
		break;
	case 'i': case 'I':
		if (!add_named(p, c, "[:alpha:]") || !add_chars(p, c, "_:"))
			return (E_FAIL);
		break;
	case 'c': case 'C':
		if (!add_named(p, c, "[:alnum:]") || !add_chars(p, c, "._:-"))
			return (E_FAIL);
		break;
	default:
		if (!category(p, c, at))
			return (E_FAIL);
		break;
	}
	return (E_CLASS);
}

static void
class_free(struct pclass *c)
{

	free(c->m);
	memset(c, 0, sizeof(*c));
}

/* charClassExpr: '[' '^'? (charRange | charClassEsc)+ ']' */
static bool
bracket(struct pparse *p)
{
	struct pclass c = { 0 };
	size_t start = p->i;
	uint32_t lo, hi;
	bool neg, ok = false;

	p->i++;			/* "[" */
	if (p->s[p->i] == '^') {
		c.neg = true;
		p->i++;
	}
	for (;;) {
		size_t at = p->i;
		char ch = p->s[p->i];

		if (ch == '\0') {
			refuse(p, start, "a class without its \"]\"");
			goto out;
		}
		if (ch == ']') {
			if (c.n == 0 && c.nnamed == 0) {
				refuse(p, at, "an empty class");
				goto out;
			}
			p->i++;
			break;
		}
		if (ch == '-' && p->s[p->i + 1] == '[') {
			refuse(p, at, "class subtraction: no POSIX bracket "
			    "expression does it");
			goto out;
		}
		if (ch == '[') {
			refuse(p, at, "an unescaped \"[\" in a class");
			goto out;
		}
		if (ch == '\\') {
			switch (escape(p, &c, &neg, &lo)) {
			case E_FAIL:
				goto out;
			case E_CLASS:
				if (neg) {
					refuse(p, at, "a complemented escape "
					    "inside a class");
					goto out;
				}
				continue;
			case E_CHAR:
				break;
			}
		} else if (ch == '-') {
			/* A "-" first or last is itself. */
			if (p->s[p->i + 1] != ']' && (c.n > 0 ||
			    c.nnamed > 0)) {
				refuse(p, at, "a \"-\" that is not first, last "
				    "or a range's");
				goto out;
			}
			lo = '-';
			p->i++;
		} else if (!utf8(p, &p->i, &lo))
			goto out;
		/* A range: the character, "-", another (not "]"). */
		hi = lo;
		if (p->s[p->i] == '-' && p->s[p->i + 1] != ']' &&
		    p->s[p->i + 1] != '\0' && p->s[p->i + 1] != '[') {
			size_t rat = p->i;

			p->i++;
			if (p->s[p->i] == '\\') {
				struct pclass dummy = { 0 };

				if (escape(p, &dummy, &neg, &hi) != E_CHAR) {
					class_free(&dummy);
					if (!p->failed)
						refuse(p, rat, "a range to a "
						    "class escape");
					goto out;
				}
			} else if (!utf8(p, &p->i, &hi))
				goto out;
			if (hi < lo) {
				refuse(p, rat, "a range backwards");
				goto out;
			}
		}
		if (!add_range(p, &c, lo, hi))
			goto out;
	}
	ok = put_class(p, &c);
out:
	class_free(&c);
	return (ok);
}

/* A multi-character escape outside a class: its own bracket. */
static bool
class_escape(struct pparse *p)
{
	struct pclass c = { 0 };
	uint32_t ch;
	bool neg, ok = false;

	switch (escape(p, &c, &neg, &ch)) {
	case E_FAIL:
		break;
	case E_CHAR:
		/* Ordinary in an ERE, or escaped as an ERE wants. */
		if (ch == '\n' || ch == '\r' || ch == '\t' || ch == '-' ||
		    ch == ']' || ch == '}')
			ok = put_cp(p, ch);
		else {
			char b[3] = { '\\', (char)ch, '\0' };

			ok = puts_(p, b);
		}
		break;
	case E_CLASS:
		c.neg = neg;
		ok = put_class(p, &c);
		break;
	}
	class_free(&c);
	return (ok);
}

/*
 * quantifier: [?*+] | '{' n (',' m?)? '}', counts up to RE_DUP_MAX.  An
 * atom taken no times ({0}, {0,0}), which matches nothing but the empty
 * string and which regcomp(3) refuses, is written as an empty group:
 * mark is where the atom's ERE begins.
 */
static bool
quantifier(struct pparse *p, size_t mark)
{
	size_t at = p->i;
	unsigned long n, m;
	char *end;

	switch (p->s[p->i]) {
	case '?': case '*': case '+':
		p->i++;
		return (put(p, p->s + at, 1));
	case '{':
		break;
	default:
		return (true);
	}
	if (p->s[p->i + 1] < '0' || p->s[p->i + 1] > '9')
		return (refuse(p, at, "a \"{\" not opening a count"));
	errno = 0;
	n = strtoul(p->s + p->i + 1, &end, 10);
	m = n;
	if (*end == ',') {
		end++;
		if (*end >= '0' && *end <= '9')
			m = strtoul(end, &end, 10);
		else
			m = ULONG_MAX;		/* open */
	}
	if (*end != '}')
		return (refuse(p, at, "a count without its \"}\""));
	if (errno != 0 || n > RE_DUP_MAX || (m != ULONG_MAX &&
	    m > RE_DUP_MAX))
		return (refuse(p, at, "a count over %d, which regcomp(3) "
		    "takes no more than", RE_DUP_MAX));
	if (m < n)
		return (refuse(p, at, "a count backwards"));
	p->i = (size_t)(end - p->s) + 1;
	if (m == 0) {
		p->out.len = mark;
		return (puts_(p, "()"));
	}
	return (put(p, p->s + at, p->i - at));
}

/* atom quantifier? */
static bool
piece(struct pparse *p)
{
	size_t at = p->i, mark = p->out.len;
	uint32_t ch;
	char c = p->s[p->i];

	switch (c) {
	case '(':
		if (++p->depth > CBL_PAT_MAX_DEPTH)
			return (refuse(p, at, "groups nested deeper than %d",
			    CBL_PAT_MAX_DEPTH));
		p->i++;
		if (!puts_(p, "(") || !regexp(p))
			return (false);
		if (p->s[p->i] != ')')
			return (refuse(p, at, "a group without its \")\""));
		p->i++;
		p->depth--;
		if (!puts_(p, ")"))
			return (false);
		break;
	case '[':
		if (!bracket(p))
			return (false);
		break;
	case '.':
		p->i++;
		if (!puts_(p, "[^\n\r]"))
			return (false);
		break;
	case '\\':
		if (!class_escape(p))
			return (false);
		break;
	case '?': case '*': case '+': case '{':
		return (refuse(p, at, "a quantifier with nothing before it"));
	case '}': case ']':
		return (refuse(p, at, "an unescaped \"%c\"", c));
	case '^': case '$':
		p->i++;
		if (!puts_(p, c == '^' ? "\\^" : "\\$"))
			return (false);
		break;
	default:
		if (!utf8(p, &p->i, &ch) || !put_cp(p, ch))
			return (false);
		break;
	}
	return (quantifier(p, mark));
}

/*
 * regExp: branch ('|' branch)*.  An empty branch, which XSD allows and
 * an ERE does not, is written as an empty group.
 */
static bool
regexp(struct pparse *p)
{
	size_t mark;

	for (;;) {
		mark = p->out.len;
		while (p->s[p->i] != '\0' && p->s[p->i] != '|' &&
		    p->s[p->i] != ')')
			if (!piece(p))
				return (false);
		if (p->out.len == mark && !puts_(p, "()"))
			return (false);
		if (p->s[p->i] != '|')
			return (true);
		p->i++;
		if (!puts_(p, "|"))
			return (false);
	}
}

char *
cbl_pattern_ere(const char *xsd, char *why, size_t whylen, size_t *pos)
{
	struct pparse p = { .s = xsd, .why = why, .whylen = whylen };

	if (why != NULL && whylen > 0)
		why[0] = '\0';
	if (xsd == NULL || strnlen(xsd, CBL_PAT_MAX_LEN + 1) >
	    CBL_PAT_MAX_LEN)
		refuse(&p, 0, "longer than %d bytes", CBL_PAT_MAX_LEN);
	else if (puts_(&p, "^(") && regexp(&p)) {
		if (xsd[p.i] == ')')
			refuse(&p, p.i, "a \")\" that closes no group");
		else
			puts_(&p, ")$");
	}
	if (p.failed) {
		free(p.out.p);
		if (pos != NULL)
			*pos = p.pos;
		return (NULL);
	}
	return (p.out.p);
}

/*
 * Matching runs in C.UTF-8, made once, for this thread only while
 * regcomp(3) and regexec(3) run: the program's own locale is untouched.
 */
static locale_t		utf8_loc;
static pthread_once_t	utf8_once = PTHREAD_ONCE_INIT;

static void
utf8_init(void)
{

	utf8_loc = newlocale(LC_CTYPE_MASK, "C.UTF-8", NULL);
}

static locale_t
utf8_locale(void)
{

	pthread_once(&utf8_once, utf8_init);
	return (utf8_loc);
}

int
cbl_pattern_init(void)
{

	return (utf8_locale() != NULL ? 0 : -1);
}

int
cbl_pattern_compile(const char *xsd, regex_t *re, char *why, size_t whylen,
    size_t *pos)
{
	locale_t loc, old;
	char *ere;
	int rc;

	if ((ere = cbl_pattern_ere(xsd, why, whylen, pos)) == NULL)
		return (-1);
	if ((loc = utf8_locale()) == NULL) {
		free(ere);
		if (why != NULL && whylen > 0)
			snprintf(why, whylen, "no C.UTF-8 locale");
		if (pos != NULL)
			*pos = 0;
		return (-1);
	}
	old = uselocale(loc);
	rc = regcomp(re, ere, REG_EXTENDED | REG_NOSUB);
	uselocale(old);
	if (rc != 0) {
		if (why != NULL && whylen > 0) {
			char msg[128];

			regerror(rc, re, msg, sizeof(msg));
			snprintf(why, whylen, "regcomp(3) refuses its ERE %s: "
			    "%s", ere, msg);
		}
		if (pos != NULL)
			*pos = 0;
		free(ere);
		return (-1);
	}
	free(ere);
	return (0);
}

/* An ERE already translated (a schema table's), compiled as above. */
int
cbl_pattern_compile_ere(const char *ere, regex_t *re)
{
	locale_t loc, old;
	int rc;

	if ((loc = utf8_locale()) == NULL)
		return (-1);
	old = uselocale(loc);
	rc = regcomp(re, ere, REG_EXTENDED | REG_NOSUB);
	uselocale(old);
	return (rc == 0 ? 0 : -1);
}

bool
cbl_pattern_match(const regex_t *re, const char *value)
{
	locale_t old;
	bool ok;

	old = uselocale(utf8_locale());
	ok = regexec(re, value, 0, NULL, 0) == 0;
	uselocale(old);
	return (ok);
}

void
cbl_pattern_free(regex_t *re)
{

	regfree(re);
}
