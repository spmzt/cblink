/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Parser for the strict YAML subset of docs/SPEC-FORMAT.md part 1: block
 * mappings, block sequences, scalars (plain, quoted, literal and folded
 * block scalars) and comments.  Everything else is rejected with a
 * file:line:column diagnostic.  Input is treated as hostile: sizes,
 * depth and node counts are bounded.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gen.h"

struct line {
	int		 no;
	const char	*s;
	size_t		 len;
	size_t		 indent;
	bool		 blank;		/* empty or comment only */
};

struct yparser {
	struct line	*lines;
	size_t		 nlines;
	size_t		 i;
	struct diags	*d;
	bool		 failed;
	size_t		 nodes;
	int		 depth;
};

static struct ynode *parse_block(struct yparser *p, size_t indent);

static void
perr(struct yparser *p, int line, size_t off, const char *fmt, const char *arg)
{

	if (p->failed)
		return;
	p->failed = true;
	diag_add(p->d, line, (int)off + 1, fmt, arg != NULL ? arg : "");
}

static struct ynode *
node_new(struct yparser *p, enum ytype type, int line, size_t off)
{
	struct ynode *n;

	if (++p->nodes > YAML_MAX_NODES) {
		perr(p, line, off, "too many nodes (limit %s)", "100000");
		return (NULL);
	}
	n = xcalloc(1, sizeof(*n));
	n->type = type;
	n->line = line;
	n->col = (int)off + 1;
	return (n);
}

void
yaml_free(struct ynode *n)
{

	if (n == NULL)
		return;
	free(n->str);
	for (size_t i = 0; i < n->npairs; i++) {
		free(n->pairs[i].key);
		yaml_free(n->pairs[i].val);
	}
	free(n->pairs);
	for (size_t i = 0; i < n->nitems; i++)
		yaml_free(n->items[i]);
	free(n->items);
	free(n);
}

const struct ynode *
ymap_get(const struct ynode *map, const char *key)
{

	if (map == NULL || map->type != Y_MAP)
		return (NULL);
	for (size_t i = 0; i < map->npairs; i++)
		if (strcmp(map->pairs[i].key, key) == 0)
			return (map->pairs[i].val);
	return (NULL);
}

/* Strict UTF-8; returns the offset of the first bad byte or -1. */
static long
utf8_check(const unsigned char *s, size_t len)
{
	size_t i, n;
	uint32_t cp, min;

	for (i = 0; i < len; i += n) {
		if (s[i] < 0x80) {
			n = 1;
			continue;
		}
		if ((s[i] & 0xe0) == 0xc0) {
			n = 2; cp = s[i] & 0x1f; min = 0x80;
		} else if ((s[i] & 0xf0) == 0xe0) {
			n = 3; cp = s[i] & 0x0f; min = 0x800;
		} else if ((s[i] & 0xf8) == 0xf0) {
			n = 4; cp = s[i] & 0x07; min = 0x10000;
		} else
			return ((long)i);
		if (len - i < n)
			return ((long)i);
		for (size_t j = 1; j < n; j++) {
			if ((s[i + j] & 0xc0) != 0x80)
				return ((long)i);
			cp = (cp << 6) | (s[i + j] & 0x3f);
		}
		if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
			return ((long)i);
	}
	return (-1);
}

/* Split into lines and apply the lexical rules. */
static bool
split_lines(struct yparser *p, const char *data, size_t len)
{
	const char *s, *e, *end = data + len;
	struct line *l;
	size_t cap = 0, k;
	long bad;
	int no = 0;

	if (len > YAML_MAX_FILE) {
		perr(p, 1, 0, "file too large (limit %s bytes)", "1048576");
		return (false);
	}
	if (len >= 3 && memcmp(data, "\xef\xbb\xbf", 3) == 0) {
		perr(p, 1, 0, "byte-order mark is not allowed%s", NULL);
		return (false);
	}
	for (s = data; s < end; s = e + 1) {
		if ((e = memchr(s, '\n', (size_t)(end - s))) == NULL)
			e = end;
		no++;
		if ((size_t)(e - s) > YAML_MAX_LINE) {
			perr(p, no, YAML_MAX_LINE, "line too long (limit %s)",
			    "4096");
			return (false);
		}
		for (k = 0; k < (size_t)(e - s); k++) {
			if (s[k] == '\0') {
				perr(p, no, k, "NUL byte%s", NULL);
				return (false);
			}
			if (s[k] == '\r') {
				perr(p, no, k, "carriage return; use LF line "
				    "endings%s", NULL);
				return (false);
			}
		}
		if ((bad = utf8_check((const unsigned char *)s,
		    (size_t)(e - s))) != -1) {
			perr(p, no, (size_t)bad, "invalid UTF-8%s", NULL);
			return (false);
		}
		if (p->nlines == cap) {
			cap = cap == 0 ? 256 : cap * 2;
			p->lines = xreallocarray(p->lines, cap, sizeof(*l));
		}
		l = &p->lines[p->nlines++];
		l->no = no;
		l->s = s;
		l->len = (size_t)(e - s);
		for (k = 0; k < l->len && s[k] == ' '; k++)
			;
		if (k < l->len && s[k] == '\t') {
			perr(p, no, k, "tabs are not allowed in indentation%s",
			    NULL);
			return (false);
		}
		l->indent = k;
		l->blank = k == l->len || s[k] == '#';
		if (e == end)
			break;
	}
	return (true);
}

static void
skip_blank(struct yparser *p)
{

	while (p->i < p->nlines && p->lines[p->i].blank)
		p->i++;
}

static bool
is_seq_item(const struct line *l, size_t off)
{

	return (off < l->len && l->s[off] == '-' &&
	    (off + 1 == l->len || l->s[off + 1] == ' '));
}

static bool
is_key_char(char c)
{

	return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	    (c >= '0' && c <= '9') || c == '_' || c == '-');
}

/* Length of "key" if "key:" followed by space or end of line, else 0. */
static size_t
map_key_len(const struct line *l, size_t off)
{
	size_t k = off;

	if (k >= l->len || !is_key_char(l->s[k]) || l->s[k] == '-' ||
	    l->s[k] == '_')
		return (0);
	while (k < l->len && is_key_char(l->s[k]))
		k++;
	if (k >= l->len || l->s[k] != ':')
		return (0);
	if (k + 1 < l->len && l->s[k + 1] != ' ')
		return (0);
	return (k - off);
}

/* Only spaces and an optional comment from "off" to end of line? */
static bool
rest_empty(const struct line *l, size_t off)
{

	while (off < l->len && l->s[off] == ' ')
		off++;
	return (off == l->len || l->s[off] == '#');
}

static void
put_utf8(struct buf *b, uint32_t cp)
{
	char u[4];

	if (cp < 0x80) {
		u[0] = (char)cp;
		buf_add(b, u, 1);
	} else if (cp < 0x800) {
		u[0] = (char)(0xc0 | (cp >> 6));
		u[1] = (char)(0x80 | (cp & 0x3f));
		buf_add(b, u, 2);
	} else if (cp < 0x10000) {
		u[0] = (char)(0xe0 | (cp >> 12));
		u[1] = (char)(0x80 | ((cp >> 6) & 0x3f));
		u[2] = (char)(0x80 | (cp & 0x3f));
		buf_add(b, u, 3);
	} else {
		u[0] = (char)(0xf0 | (cp >> 18));
		u[1] = (char)(0x80 | ((cp >> 12) & 0x3f));
		u[2] = (char)(0x80 | ((cp >> 6) & 0x3f));
		u[3] = (char)(0x80 | (cp & 0x3f));
		buf_add(b, u, 4);
	}
}

static int
hexval(char c)
{

	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return (-1);
}

static struct ynode *
finish_scalar(struct yparser *p, struct ynode *n, struct buf *b,
    const struct line *l, size_t off)
{

	if (b->len > YAML_MAX_SCALAR) {
		perr(p, l->no, off, "scalar too long (limit %s bytes)",
		    "65536");
		buf_free(b);
		yaml_free(n);
		return (NULL);
	}
	n->str = b->p != NULL ? b->p : xstrdup("");
	n->len = b->len;
	return (n);
}

static struct ynode *
parse_dq(struct yparser *p, const struct line *l, size_t off)
{
	struct ynode *n;
	struct buf b;
	size_t k = off + 1;
	uint32_t cp;
	int digits, h;

	if ((n = node_new(p, Y_SCALAR, l->no, off)) == NULL)
		return (NULL);
	n->quoted = true;
	buf_init(&b);
	for (;;) {
		if (k >= l->len) {
			perr(p, l->no, off, "unterminated double-quoted scalar "
			    "(multi-line scalars are not supported)%s", NULL);
			goto fail;
		}
		if (l->s[k] == '"')
			break;
		if (l->s[k] != '\\') {
			buf_add(&b, &l->s[k++], 1);
			continue;
		}
		if (++k >= l->len) {
			perr(p, l->no, k - 1, "incomplete escape%s", NULL);
			goto fail;
		}
		digits = 0;
		switch (l->s[k]) {
		case '\\': buf_add(&b, "\\", 1); break;
		case '"': buf_add(&b, "\"", 1); break;
		case '/': buf_add(&b, "/", 1); break;
		case 'n': buf_add(&b, "\n", 1); break;
		case 't': buf_add(&b, "\t", 1); break;
		case 'r': buf_add(&b, "\r", 1); break;
		case 'x': digits = 2; break;
		case 'u': digits = 4; break;
		case 'U': digits = 8; break;
		default:
			perr(p, l->no, k - 1, "unsupported escape '\\%s'",
			    (char[2]){ l->s[k], '\0' });
			goto fail;
		}
		if (digits > 0) {
			cp = 0;
			for (int j = 1; j <= digits; j++) {
				if (k + (size_t)j >= l->len ||
				    (h = hexval(l->s[k + (size_t)j])) < 0) {
					perr(p, l->no, k - 1,
					    "bad hexadecimal escape%s", NULL);
					goto fail;
				}
				cp = cp * 16 + (uint32_t)h;
			}
			if (cp == 0 || cp > 0x10ffff ||
			    (cp >= 0xd800 && cp <= 0xdfff)) {
				perr(p, l->no, k - 1, "escape is not a valid "
				    "non-NUL Unicode scalar value%s", NULL);
				goto fail;
			}
			put_utf8(&b, cp);
			k += (size_t)digits;
		}
		k++;
	}
	if (!rest_empty(l, k + 1)) {
		perr(p, l->no, k + 1, "unexpected text after quoted scalar%s",
		    NULL);
		goto fail;
	}
	p->i++;
	return (finish_scalar(p, n, &b, l, off));
fail:
	buf_free(&b);
	yaml_free(n);
	return (NULL);
}

static struct ynode *
parse_sq(struct yparser *p, const struct line *l, size_t off)
{
	struct ynode *n;
	struct buf b;
	size_t k = off + 1;

	if ((n = node_new(p, Y_SCALAR, l->no, off)) == NULL)
		return (NULL);
	n->quoted = true;
	buf_init(&b);
	for (;;) {
		if (k >= l->len) {
			perr(p, l->no, off, "unterminated single-quoted scalar "
			    "(multi-line scalars are not supported)%s", NULL);
			buf_free(&b);
			yaml_free(n);
			return (NULL);
		}
		if (l->s[k] == '\'') {
			if (k + 1 < l->len && l->s[k + 1] == '\'') {
				buf_add(&b, "'", 1);
				k += 2;
				continue;
			}
			break;
		}
		buf_add(&b, &l->s[k++], 1);
	}
	if (!rest_empty(l, k + 1)) {
		perr(p, l->no, k + 1, "unexpected text after quoted scalar%s",
		    NULL);
		buf_free(&b);
		yaml_free(n);
		return (NULL);
	}
	p->i++;
	return (finish_scalar(p, n, &b, l, off));
}

/* "|" or ">" block scalar; "parent" is the indentation of its owner. */
static struct ynode *
parse_block_scalar(struct yparser *p, const struct line *l, size_t off,
    size_t parent)
{
	struct ynode *n;
	struct buf b;
	bool folded = l->s[off] == '>', more_prev = false, first = true;
	char chomp = 'c';
	size_t k = off + 1, bi = 0, pending_nl = 0;
	const struct line *c;

	if (k < l->len && (l->s[k] == '-' || l->s[k] == '+'))
		chomp = l->s[k++];
	if (k < l->len && l->s[k] >= '1' && l->s[k] <= '9') {
		perr(p, l->no, k, "explicit indentation indicators are not "
		    "supported%s", NULL);
		return (NULL);
	}
	if (!rest_empty(l, k)) {
		perr(p, l->no, k, "unexpected text after block scalar "
		    "indicator%s", NULL);
		return (NULL);
	}
	if ((n = node_new(p, Y_SCALAR, l->no, off)) == NULL)
		return (NULL);
	buf_init(&b);
	for (p->i++; p->i < p->nlines; p->i++) {
		c = &p->lines[p->i];
		if (c->indent == c->len) {		/* empty line */
			pending_nl++;
			continue;
		}
		if (bi == 0) {
			if (c->indent <= parent)
				break;
			bi = c->indent;
		} else if (c->indent < bi) {
			if (c->indent > parent) {
				perr(p, c->no, c->indent, "block scalar line "
				    "is less indented than its first line%s",
				    NULL);
				buf_free(&b);
				yaml_free(n);
				return (NULL);
			}
			break;
		}
		bool more = c->indent > bi;

		if (!first) {
			/*
			 * Literal: every break is kept.  Folded: a single
			 * break between ordinary lines becomes a space and
			 * each blank line a newline; more-indented lines keep
			 * their breaks.
			 */
			size_t nl = pending_nl;

			if (!folded || more || more_prev)
				nl++;
			if (nl == 0)
				buf_add(&b, " ", 1);
			for (; nl > 0; nl--)
				buf_add(&b, "\n", 1);
		}
		pending_nl = 0;
		buf_add(&b, c->s + bi, c->len - bi);
		first = false;
		more_prev = more;
		if (b.len > YAML_MAX_SCALAR)
			break;
	}
	/* Trailing line breaks: clip keeps one, strip none, keep all. */
	if (!first) {
		if (chomp == 'c')
			buf_add(&b, "\n", 1);
		else if (chomp == '+')
			for (size_t j = 0; j <= pending_nl; j++)
				buf_add(&b, "\n", 1);
	}
	return (finish_scalar(p, n, &b, l, off));
}

static struct ynode *
parse_plain(struct yparser *p, const struct line *l, size_t off)
{
	struct ynode *n;
	struct buf b;
	size_t e = off;

	while (e < l->len && !(l->s[e] == '#' && e > off && l->s[e - 1] == ' '))
		e++;
	while (e > off && l->s[e - 1] == ' ')
		e--;
	for (size_t k = off; k + 1 < e; k++) {
		if (l->s[k] == ':' && l->s[k + 1] == ' ') {
			perr(p, l->no, k, "plain scalars must not contain "
			    "': '; quote the value%s", NULL);
			return (NULL);
		}
	}
	if (e > off && l->s[e - 1] == ':') {
		perr(p, l->no, e - 1, "plain scalars must not end with ':'%s",
		    NULL);
		return (NULL);
	}
	if ((n = node_new(p, Y_SCALAR, l->no, off)) == NULL)
		return (NULL);
	buf_init(&b);
	buf_add(&b, l->s + off, e - off);
	p->i++;
	return (finish_scalar(p, n, &b, l, off));
}

/* A scalar starting at "off" on the current line. */
static struct ynode *
parse_inline(struct yparser *p, size_t off, size_t parent)
{
	const struct line *l = &p->lines[p->i];
	char c = l->s[off];

	switch (c) {
	case '"':
		return (parse_dq(p, l, off));
	case '\'':
		return (parse_sq(p, l, off));
	case '|':
	case '>':
		return (parse_block_scalar(p, l, off, parent));
	case '[':
	case '{':
		perr(p, l->no, off, "flow %s are not supported; use block "
		    "style", c == '[' ? "sequences ('[')" : "mappings ('{')");
		return (NULL);
	case '&':
		perr(p, l->no, off, "anchors are not supported%s", NULL);
		return (NULL);
	case '*':
		perr(p, l->no, off, "aliases are not supported%s", NULL);
		return (NULL);
	case '!':
		perr(p, l->no, off, "tags are not supported%s", NULL);
		return (NULL);
	case '?':
		perr(p, l->no, off, "complex keys are not supported%s", NULL);
		return (NULL);
	case '%':
	case '@':
	case '`':
	case ',':
	case ']':
	case '}':
		perr(p, l->no, off, "unexpected character '%s'",
		    (char[2]){ c, '\0' });
		return (NULL);
	default:
		return (parse_plain(p, l, off));
	}
}

/* The value after "key:" (inline or on the following lines). */
static struct ynode *
parse_value(struct yparser *p, size_t vo, size_t col0, const char *key,
    int kline, size_t koff)
{
	const struct line *l;

	l = &p->lines[p->i];
	while (vo < l->len && l->s[vo] == ' ')
		vo++;
	if (vo < l->len && l->s[vo] != '#')
		return (parse_inline(p, vo, col0));
	p->i++;
	skip_blank(p);
	if (p->i < p->nlines) {
		l = &p->lines[p->i];
		if (l->indent > col0)
			return (parse_block(p, l->indent));
		if (l->indent == col0 && is_seq_item(l, col0))
			return (parse_block(p, col0));
	}
	perr(p, kline, koff, "missing value for '%s' (write an empty "
	    "sequence or mapping by omitting the key)", key);
	return (NULL);
}

/*
 * A mapping whose entries start at column "col0"; the first entry may
 * begin mid-line (inside "- key: value").
 */
static struct ynode *
parse_map(struct yparser *p, size_t col0, size_t firstoff)
{
	const struct line *l = &p->lines[p->i];
	struct ynode *map, *val;
	size_t off = firstoff, klen, cap = 0;
	char *key;

	if ((map = node_new(p, Y_MAP, l->no, firstoff)) == NULL)
		return (NULL);
	for (;;) {
		l = &p->lines[p->i];
		if (is_seq_item(l, off)) {
			perr(p, l->no, off, "unexpected sequence item in a "
			    "mapping%s", NULL);
			goto fail;
		}
		if ((klen = map_key_len(l, off)) == 0) {
			if (l->s[off] == '"' || l->s[off] == '\'')
				perr(p, l->no, off, "quoted keys are not "
				    "supported%s", NULL);
			else if (l->s[off] == '?')
				perr(p, l->no, off, "complex keys are not "
				    "supported%s", NULL);
			else if (l->len - off >= 3 &&
			    (memcmp(l->s + off, "---", 3) == 0 ||
			    memcmp(l->s + off, "...", 3) == 0))
				perr(p, l->no, off, "multiple documents "
				    "are not supported%s", NULL);
			else
				perr(p, l->no, off, "expected 'key: value'%s",
				    NULL);
			goto fail;
		}
		key = xstrndup(l->s + off, klen);
		for (size_t j = 0; j < map->npairs; j++) {
			if (strcmp(map->pairs[j].key, key) == 0) {
				char where[48];

				snprintf(where, sizeof(where), "%d:%d",
				    map->pairs[j].line, map->pairs[j].col);
				diag_add(p->d, l->no, (int)off + 1,
				    "duplicate key '%s' (first defined at %s)",
				    key, where);
				p->failed = true;
				free(key);
				goto fail;
			}
		}
		if (map->npairs == cap) {
			cap = cap == 0 ? 8 : cap * 2;
			map->pairs = xreallocarray(map->pairs, cap,
			    sizeof(*map->pairs));
		}
		map->pairs[map->npairs].key = key;
		map->pairs[map->npairs].line = l->no;
		map->pairs[map->npairs].col = (int)off + 1;
		map->pairs[map->npairs].val = NULL;
		map->npairs++;
		val = parse_value(p, off + klen + 1, col0, key, l->no, off);
		if (val == NULL)
			goto fail;
		map->pairs[map->npairs - 1].val = val;

		skip_blank(p);
		if (p->i >= p->nlines)
			break;
		l = &p->lines[p->i];
		if (l->indent < col0)
			break;
		if (l->indent > col0) {
			perr(p, l->no, l->indent, "unexpected indentation%s",
			    NULL);
			goto fail;
		}
		if (is_seq_item(l, col0))
			break;		/* the parent sequence continues */
		off = col0;
	}
	return (map);
fail:
	yaml_free(map);
	return (NULL);
}

static struct ynode *
parse_seq(struct yparser *p, size_t col0)
{
	const struct line *l = &p->lines[p->i];
	struct ynode *seq, *item;
	size_t off, cap = 0;

	if ((seq = node_new(p, Y_SEQ, l->no, col0)) == NULL)
		return (NULL);
	for (;;) {
		l = &p->lines[p->i];
		off = col0 + 1;
		while (off < l->len && l->s[off] == ' ')
			off++;
		if (off >= l->len || l->s[off] == '#') {
			/* The item is a block on the following lines. */
			p->i++;
			skip_blank(p);
			if (p->i >= p->nlines ||
			    p->lines[p->i].indent <= col0) {
				perr(p, l->no, col0, "missing sequence item%s",
				    NULL);
				goto fail;
			}
			item = parse_block(p, p->lines[p->i].indent);
		} else if (map_key_len(l, off) > 0) {
			p->depth++;
			if (p->depth > YAML_MAX_DEPTH) {
				perr(p, l->no, off, "nesting too deep (limit "
				    "%s)", "32");
				goto fail;
			}
			item = parse_map(p, off, off);
			p->depth--;
		} else
			item = parse_inline(p, off, col0);
		if (item == NULL)
			goto fail;
		if (seq->nitems == cap) {
			cap = cap == 0 ? 8 : cap * 2;
			seq->items = xreallocarray(seq->items, cap,
			    sizeof(*seq->items));
		}
		seq->items[seq->nitems++] = item;

		skip_blank(p);
		if (p->i >= p->nlines)
			break;
		l = &p->lines[p->i];
		if (l->indent < col0)
			break;
		if (l->indent > col0) {
			perr(p, l->no, l->indent, "unexpected indentation%s",
			    NULL);
			goto fail;
		}
		if (!is_seq_item(l, col0))
			break;		/* "key:\n- a\nnext: b" */
	}
	return (seq);
fail:
	yaml_free(seq);
	return (NULL);
}

static struct ynode *
parse_block(struct yparser *p, size_t indent)
{
	const struct line *l = &p->lines[p->i];
	struct ynode *n;

	if (++p->depth > YAML_MAX_DEPTH) {
		perr(p, l->no, indent, "nesting too deep (limit %s)", "32");
		return (NULL);
	}
	if (is_seq_item(l, indent))
		n = parse_seq(p, indent);
	else if (map_key_len(l, indent) > 0)
		n = parse_map(p, indent, indent);
	else if (indent == 0)
		n = parse_map(p, 0, 0);	/* reports what is wrong */
	else
		n = parse_inline(p, indent, indent - 1);
	p->depth--;
	return (n);
}

struct ynode *
yaml_parse(const char *data, size_t len, struct diags *d)
{
	struct yparser p = { .d = d };
	struct ynode *root = NULL;
	const struct line *l;

	if (!split_lines(&p, data, len))
		goto out;
	skip_blank(&p);
	if (p.i < p.nlines) {
		l = &p.lines[p.i];
		if (l->indent == 0 && l->len >= 3 &&
		    memcmp(l->s, "---", 3) == 0 && rest_empty(l, 3)) {
			p.i++;
			skip_blank(&p);
		} else if (l->indent == 0 && l->s[0] == '%') {
			perr(&p, l->no, 0, "directives are not supported%s",
			    NULL);
			goto out;
		}
	}
	if (p.i >= p.nlines) {
		perr(&p, 1, 0, "empty document%s", NULL);
		goto out;
	}
	l = &p.lines[p.i];
	if (l->indent != 0) {
		perr(&p, l->no, l->indent, "top-level content must not be "
		    "indented%s", NULL);
		goto out;
	}
	root = parse_block(&p, 0);
	if (root != NULL) {
		skip_blank(&p);
		if (p.i < p.nlines) {
			l = &p.lines[p.i];
			perr(&p, l->no, l->indent, "unexpected content after "
			    "the document%s", NULL);
			yaml_free(root);
			root = NULL;
		}
	}
out:
	if (p.failed && root != NULL) {
		yaml_free(root);
		root = NULL;
	}
	free(p.lines);
	return (root);
}
