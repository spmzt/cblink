# Settings shared by libcblink and its tests.
#
# The same tree builds three ways:
#   - in-tree (/usr/src/lib/libcblink): SRCTOP is defined; libcbor is the
#     base private library (LIBADD cbor, headers from contrib/libcbor);
#   - out-of-tree with base make(1) and bsd.*.mk;
#   - as the devel/cblink port: out of tree, with PREFIX, LOCALBASE,
#     CFLAGS, LDFLAGS and OPENSSLINC/OPENSSLLIB (USES=ssl) from the
#     port's environment.
# Out of tree, libcbor comes from devel/libcbor in ${LOCALBASE}.

CSTD?=		c23
WARNS?=		6

.if defined(SRCTOP) && !defined(CBLINK_OUT_OF_TREE)
CBLINK_INTREE=	yes
CBOR_CFLAGS=	-I${SRCTOP}/contrib/libcbor/src -I${SRCTOP}/lib/libcbor
.else
PREFIX?=	/usr/local
LOCALBASE?=	/usr/local
LIBDIR?=	${PREFIX}/lib
SHLIBDIR?=	${LIBDIR}
INCLUDEDIR?=	${PREFIX}/include
MANDIR?=	${PREFIX}/share/man/man
TESTSBASE?=	${PREFIX}/tests
# devel/libcbor.  -idirafter and a full library path keep base OpenSSL
# ahead of any OpenSSL that may also be installed under ${LOCALBASE}.
CBOR_CFLAGS=	-idirafter ${LOCALBASE}/include
CBOR_LDADD=	${LOCALBASE}/lib/libcbor.so
# Base has libcbor only as a private library, without headers.
.if !exists(${LOCALBASE}/include/cbor.h) && !make(clean) && \
    !make(cleandir) && !make(cleanobj) && !make(obj)
.error libcbor not found in ${LOCALBASE}: pkg install libcbor, or set LOCALBASE
.endif
# OpenSSL: base by default, which has the SCTP support DTLS over SCTP
# needs.  USES=ssl in the port names its choice in OPENSSLINC and
# OPENSSLLIB; with one built without SCTP (LibreSSL, or an OpenSSL port
# with its SCTP option off) the library has no DTLS over SCTP
# (cbl_features()).
.if defined(OPENSSLINC) && ${OPENSSLINC} != "/usr/include"
SSL_CFLAGS=	-I${OPENSSLINC}
.endif
.if defined(OPENSSLLIB) && ${OPENSSLLIB} != "/usr/lib"
SSL_LDFLAGS=	-L${OPENSSLLIB}
.endif
.endif
SSL_CFLAGS?=
SSL_LDFLAGS?=
