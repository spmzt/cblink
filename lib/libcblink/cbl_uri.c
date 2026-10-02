/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Endpoint URIs:
 *	tcp://host:port		sctp://h1[,h2...]:port
 *	unix:/path
 * IPv6 literals are bracketed.  Ports are numeric.  "*" as the host
 * means the wildcard address (listeners only).
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <netinet/in.h>

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_impl.h"

#define	ERR(...)	do {						\
	if (err != NULL)						\
		snprintf(err, errlen, __VA_ARGS__);			\
	return (EINVAL);						\
} while (0)

static const struct {
	const char		*scheme;
	enum cbl_transport	 transport;
} schemes[] = {
	{ "tcp://", CBL_TR_TCP },
	{ "sctp://", CBL_TR_SCTP },
	{ "unix:", CBL_TR_UNIX },
};

int
cbl_uri_parse(const char *s, struct cbl_uri *u, char *err, size_t errlen)
{
	const char *rest, *colon;
	size_t i, hlen;
	char *end;
	long port;

	memset(u, 0, sizeof(*u));
	if (s == NULL)
		ERR("no URI");
	for (i = 0; i < nitems(schemes); i++)
		if (strncmp(s, schemes[i].scheme,
		    strlen(schemes[i].scheme)) == 0)
			break;
	if (i == nitems(schemes))
		ERR("unknown URI scheme in '%s'", s);
	u->transport = schemes[i].transport;
	rest = s + strlen(schemes[i].scheme);

	if (u->transport == CBL_TR_UNIX) {
		/* unix:/path or unix:///path */
		if (strncmp(rest, "//", 2) == 0)
			rest += 2;
		if (rest[0] != '/')
			ERR("AF_UNIX path must be absolute");
		if (strlen(rest) >= sizeof(u->path) ||
		    strlen(rest) >= sizeof(((struct sockaddr_un *)0)->sun_path))
			ERR("AF_UNIX path too long");
		strlcpy(u->path, rest, sizeof(u->path));
		return (0);
	}

	/* host[,host...]:port, where a host may be [v6]. */
	colon = strrchr(rest, ':');
	if (colon == NULL || colon == rest)
		ERR("missing host or port in '%s'", s);
	hlen = colon - rest;
	if (hlen >= sizeof(u->host))
		ERR("host list too long");
	memcpy(u->host, rest, hlen);
	u->host[hlen] = '\0';
	if (u->transport != CBL_TR_SCTP && strchr(u->host, ',') != NULL)
		ERR("only sctp:// accepts several hosts");
	for (const char *h = u->host; *h != '\0';) {
		size_t n = strcspn(h, ",");

		if (n == 0)
			ERR("empty host in '%s'", s);
		if (memchr(h, ':', n) != NULL &&
		    (h[0] != '[' || h[n - 1] != ']'))
			ERR("IPv6 addresses must be bracketed");
		h += n;
		if (*h == ',')
			h++;
	}
	errno = 0;
	port = strtol(colon + 1, &end, 10);
	if (errno != 0 || *end != '\0' || end == colon + 1 || port < 0 ||
	    port > 65535)
		ERR("bad port in '%s'", s);
	snprintf(u->port, sizeof(u->port), "%ld", port);
	return (0);
}

/* Resolve the host list into u->addr[].  Numeric ports only. */
int
cbl_uri_resolve(struct cbl_uri *u, bool passive, char *err, size_t errlen)
{
	struct addrinfo hints, *res, *ai;
	char hosts[sizeof(u->host)], *h, *next;
	size_t len;
	int rv;

	u->naddr = 0;
	if (u->transport == CBL_TR_UNIX) {
		struct sockaddr_un *sun = (struct sockaddr_un *)&u->addr[0];

		sun->sun_family = AF_UNIX;
		strlcpy(sun->sun_path, u->path, sizeof(sun->sun_path));
		sun->sun_len = SUN_LEN(sun);
		u->addrlen[0] = sun->sun_len;
		u->naddr = 1;
		return (0);
	}
	strlcpy(hosts, u->host, sizeof(hosts));
	for (h = hosts; h != NULL; h = next) {
		if ((next = strchr(h, ',')) != NULL)
			*next++ = '\0';
		len = strlen(h);
		if (len >= 2 && h[0] == '[' && h[len - 1] == ']') {
			h[len - 1] = '\0';
			h++;
		}
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_flags = AI_NUMERICSERV | (passive ? AI_PASSIVE : 0);
		switch (u->transport) {
		case CBL_TR_SCTP:
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_SCTP;
			break;
		default:
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;
			break;
		}
		if (strcmp(h, "*") == 0) {
			/*
			 * The IPv6 wildcard when there is one, whatever order
			 * the resolver prefers: that socket takes IPv4 too
			 * (cbl_uri_dualstack()).
			 */
			hints.ai_family = AF_INET6;
			rv = getaddrinfo(NULL, u->port, &hints, &res);
			if (rv != 0) {
				hints.ai_family = AF_UNSPEC;
				rv = getaddrinfo(NULL, u->port, &hints, &res);
			}
		} else
			rv = getaddrinfo(h, u->port, &hints, &res);
		if (rv != 0)
			ERR("cannot resolve '%s': %s", h, gai_strerror(rv));
		for (ai = res; ai != NULL && u->naddr < CBL_URI_MAXADDR;
		    ai = ai->ai_next) {
			if (ai->ai_addrlen > sizeof(u->addr[0]))
				continue;
			memcpy(&u->addr[u->naddr], ai->ai_addr, ai->ai_addrlen);
			u->addrlen[u->naddr++] = ai->ai_addrlen;
			/* SCTP multihoming: one address per listed host. */
			if (u->transport == CBL_TR_SCTP)
				break;
		}
		freeaddrinfo(res);
	}
	if (u->naddr == 0)
		ERR("no usable address for '%s'", u->host);
	return (0);
}

/*
 * "*" listens on every address: one IPv6 socket that also takes IPv4
 * (IPV6_V6ONLY off), whatever net.inet6.ip6.v6only says.
 */
bool
cbl_uri_dualstack(const struct cbl_uri *u)
{

	return (strcmp(u->host, "*") == 0 && u->naddr > 0 &&
	    u->addr[0].ss_family == AF_INET6);
}
