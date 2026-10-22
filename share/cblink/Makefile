# Data files: the YANG modules wire version 2 is made of (the framework's
# structures, the control family, ietf-sid-file for GET-SID) with their
# .sid files, cblink.mk for programs built from modules, and cblink.pc
# for pkg-config.

.if !defined(SRCTOP) || defined(CBLINK_OUT_OF_TREE)
PREFIX?=	/usr/local
SHAREDIR?=	${PREFIX}/share
LIBDATADIR?=	${PREFIX}/libdata
# libcbor from devel/libcbor, which has its own libcbor.pc.
PC_REQUIRES=	libcbor
PC_LIBS=	-lssl -lcrypto -lpthread
.else
PREFIX=		/usr
LIBDATADIR?=	/usr/libdata
# In the base system libcbor is a private library without a .pc file.
PC_REQUIRES=
PC_LIBS=	-lprivatecbor -lssl -lcrypto -lpthread
.endif

FILESGROUPS=	YANG MK PC

YANG=		${.CURDIR}/../yang/cblink@2026-10-13.yang \
		${.CURDIR}/../yang/cblink@2026-10-13.sid \
		${.CURDIR}/../yang/cblink-ctrl@2026-10-13.yang \
		${.CURDIR}/../yang/cblink-ctrl@2026-10-13.sid \
		${.CURDIR}/../yang/ietf-sid-file@2024-07-31.yang \
		${.CURDIR}/../yang/ietf-sid-file@2024-07-31.sid
YANGDIR=	${SHAREDIR}/cblink/yang
MK=		cblink.mk
MKDIR=		${SHAREDIR}/cblink
PC=		cblink.pc
PCDIR=		${LIBDATADIR}/pkgconfig

# One version, the one in the header.
CBLINK_H=	${.CURDIR}/../../lib/libcblink/cblink.h
VERSION!=	awk '$$2 ~ /^CBLINK_VERSION_(MAJOR|MINOR|PATCH)$$/ \
		    { v = v (v == "" ? "" : ".") $$3 } END { print v }' \
		    ${CBLINK_H}

CLEANFILES=	cblink.pc
cblink.pc: cblink.pc.in ${CBLINK_H}
	sed -e 's|%%PREFIX%%|${PREFIX}|' -e 's|%%VERSION%%|${VERSION}|' \
	    -e 's|%%REQUIRES%%|${PC_REQUIRES}|' \
	    -e 's|%%LIBS_PRIVATE%%|${PC_LIBS}|' \
	    ${.CURDIR}/cblink.pc.in > ${.TARGET}

.include <bsd.prog.mk>
