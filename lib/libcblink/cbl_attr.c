/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Read access to decoded messages: the header, the body's items by SID
 * (cbl_msg_sid_raw(), cbl_msg.c), what an error said.
 */

#include <errno.h>
#include <string.h>

#include "cbl_impl.h"
#include "cbl_schema.h"

uint16_t
cbl_msg_family(const cbl_msg *msg)
{

	return (msg != NULL ? msg->hdr.family : 0);
}

uint16_t
cbl_msg_cmd(const cbl_msg *msg)
{

	return (msg != NULL ? msg->hdr.cmd : 0);
}

uint32_t
cbl_msg_flags(const cbl_msg *msg)
{

	return (msg != NULL ? msg->hdr.flags : 0);
}

uint32_t
cbl_msg_seq(const cbl_msg *msg)
{

	return (msg != NULL ? msg->hdr.seq : 0);
}

uint32_t
cbl_msg_stream(const cbl_msg *msg)
{

	return (msg != NULL ? msg->hdr.stream : 0);
}

size_t
cbl_msg_len(const cbl_msg *msg)
{

	if (msg == NULL)
		return (0);
	return (msg->finalized ? msg->len : 0);
}

const cbl_attr *
cbl_msg_body(const cbl_msg *msg)
{

	if (msg == NULL || !msg->decoded)
		return (NULL);
	return (msg->nodes != NULL ? &msg->nodes[0] : &msg->empty);
}

/* Binary search: map children are sorted by key. */
const cbl_attr *
cbl_map_lookup(const cbl_attr *map, int64_t key)
{
	uint32_t lo, hi, mid;

	if (map == NULL || map->kind != CBL_K_NEST)
		return (NULL);
	lo = 0;
	hi = map->count;
	while (lo < hi) {
		mid = lo + (hi - lo) / 2;
		if (map->child[mid].key == key)
			return (&map->child[mid]);
		if (map->child[mid].key < key)
			lo = mid + 1;
		else
			hi = mid;
	}
	return (NULL);
}

int
cbl_msg_err_code(const cbl_msg *msg)
{

	/* Frames that carry an outcome: errors, resets and closes. */
	if (msg == NULL || (msg->hdr.flags & (CBL_F_ERROR | CBL_F_NOTIFY |
	    CBL_F_S_RESET | CBL_F_S_CLOSE)) == 0)
		return (0);
	return (msg->err_code);
}

const char *
cbl_msg_err_str(const cbl_msg *msg)
{

	return (msg != NULL ? msg->err_str : NULL);
}

/* The error's node of family 1's: error-path a SID alone (cbl_fw.c). */
uint64_t
cbl_msg_err_sid(const cbl_msg *msg)
{

	return (msg != NULL ? msg->err_ysid : 0);
}

/* The error's path: error-path's elements (cbl_fw.c). */
size_t
cbl_msg_err_path(const cbl_msg *msg, struct cbl_path_elem *path, size_t max)
{
	size_t n;

	if (msg == NULL)
		return (0);
	for (n = 0; n < msg->err_npath; n++)
		if (msg->err_pathv[n] > UINT32_MAX)
			return (0);	/* malformed path: report none */
	for (n = 0; n < msg->err_npath && n < max; n++) {
		path[n].index = false;
		path[n].v = (uint32_t)msg->err_pathv[n];
	}
	return (msg->err_npath);
}

int
cbl_msg_err_miss_type(const cbl_msg *msg)
{

	return (msg != NULL ? msg->err_miss : -1);
}

int
cbl_msg_err_cookie(const cbl_msg *msg, const void **pp, size_t *lenp)
{

	if (msg == NULL || pp == NULL || lenp == NULL)
		return (EINVAL);
	if (!msg->has_err_cookie)
		return (ENOENT);
	*pp = msg->err_cookiep;
	*lenp = msg->err_cookielen;
	return (0);
}
