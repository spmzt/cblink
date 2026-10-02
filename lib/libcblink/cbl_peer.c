/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Peer identity: the same accessors for every transport (direct mTLS,
 * AF_UNIX credentials).
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_impl.h"

void
cbl_peer_clear(struct cbl_peer *peer)
{

	free(peer->subject);
	free(peer->issuer);
	for (size_t i = 0; i < peer->nsans; i++)
		free(peer->sans[i]);
	free(peer->sans);
	memset(peer, 0, sizeof(*peer));
}

const cbl_peer *
cbl_conn_peer(const cbl_conn *conn)
{

	return (conn != NULL ? &conn->peer : NULL);
}

uint32_t
cbl_peer_flags(const cbl_peer *peer)
{

	return (peer != NULL ? peer->flags : 0);
}

enum cbl_transport
cbl_peer_transport(const cbl_peer *peer)
{

	return (peer != NULL ? peer->transport : CBL_TR_TCP);
}

const char *
cbl_peer_subject(const cbl_peer *peer)
{

	return (peer != NULL ? peer->subject : NULL);
}

const char *
cbl_peer_issuer(const cbl_peer *peer)
{

	return (peer != NULL ? peer->issuer : NULL);
}

size_t
cbl_peer_san_count(const cbl_peer *peer)
{

	return (peer != NULL ? peer->nsans : 0);
}

const char *
cbl_peer_san(const cbl_peer *peer, size_t i)
{

	if (peer == NULL || i >= peer->nsans)
		return (NULL);
	return (peer->sans[i]);
}

int
cbl_peer_fingerprint(const cbl_peer *peer, const char *alg, uint8_t *buf,
    size_t *lenp)
{
	const uint8_t *fp;
	size_t len;

	if (peer == NULL || alg == NULL || buf == NULL || lenp == NULL)
		return (EINVAL);
	if (strcmp(alg, "sha256") == 0) {
		if (!peer->has_sha256)
			return (ENOENT);
		fp = peer->fp_sha256;
		len = sizeof(peer->fp_sha256);
	} else if (strcmp(alg, "sha1") == 0) {
		if (!peer->has_sha1)
			return (ENOENT);
		fp = peer->fp_sha1;
		len = sizeof(peer->fp_sha1);
	} else
		return (EINVAL);
	if (*lenp < len)
		return (ENOSPC);
	memcpy(buf, fp, len);
	*lenp = len;
	return (0);
}

int
cbl_peer_addr(const cbl_peer *peer, struct sockaddr_storage *ss,
    socklen_t *lenp)
{

	if (peer == NULL || ss == NULL)
		return (EINVAL);
	if (peer->addrlen == 0)
		return (ENOENT);
	memcpy(ss, &peer->addr, peer->addrlen);
	if (lenp != NULL)
		*lenp = peer->addrlen;
	return (0);
}

int
cbl_peer_cred(const cbl_peer *peer, uid_t *uidp, gid_t *gidp)
{

	if (peer == NULL)
		return (EINVAL);
	if (!peer->has_cred)
		return (ENOENT);
	if (uidp != NULL)
		*uidp = peer->uid;
	if (gidp != NULL)
		*gidp = peer->gid;
	return (0);
}

/* Forget certificate identity; keep the address and credentials. */
void
cbl_peer_clear_identity(struct cbl_peer *peer)
{

	free(peer->subject);
	free(peer->issuer);
	for (size_t i = 0; i < peer->nsans; i++)
		free(peer->sans[i]);
	free(peer->sans);
	peer->subject = peer->issuer = NULL;
	peer->sans = NULL;
	peer->nsans = 0;
	peer->has_sha1 = peer->has_sha256 = false;
	peer->flags &= ~CBL_PEER_AUTHENTICATED;
}
