/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What the YANG parts of the library share and do not export: the
 * codec's reading of a struct, the validator's parsing of a default,
 * for the instance tree (cbl_data.c).
 */

#ifndef _CBL_YIMPL_H_
#define	_CBL_YIMPL_H_

#include <stdbool.h>
#include <stdint.h>

#include "cbl_schema.h"

/* Whether child n has a value in struct p (its case's, if in a choice). */
bool	cbl_ypresent(const struct cbl_ynode *n, const void *p);
/* n's case, and its choices', set in struct p; EINVAL: another's is. */
int	cbl_yset_case(const struct cbl_ynode *n, void *p);
/*
 * A value of type t, leaf or leaf-list n's, from its canonical string s
 * into out, as its member is (what it points to in a; a string's, s
 * itself).  EOPNOTSUPP: a type not read from a string.
 */
int	cbl_yvalue_parse(const struct cbl_ynode *n, const struct cbl_ytype *t,
	    const char *s, void *out, cbl_yarena *a);
/* Leaf or leaf-list n's k-th default into out, as its member is. */
int	cbl_ydefault_parse(const struct cbl_ynode *n, uint16_t k, void *out,
	    cbl_yarena *a);

/*
 * An instance-identifier's YANG-CBOR (RFC 9254 section 6.13.1): a SID,
 * or [SID, values...]: *node, the node of schema s it names, and *vals,
 * the keys of the lists from the top down to it, then a leaf-list
 * entry's value, each as its member is, allocated in a.
 */
int	cbl_yiid_read(const struct cbl_yschema *s, const struct cbl_bytes *v,
	    const struct cbl_ynode **node, const void ***vals, size_t *nvals,
	    cbl_yarena *a);

#endif /* !_CBL_YIMPL_H_ */
