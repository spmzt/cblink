# Data files: the control family spec, cblink.mk for programs built from
# specs, and cblink.pc for pkg-config.

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

FILESGROUPS=	SPECS MK PC

SPECS=		specs/control.yaml
SPECSDIR=	${SHAREDIR}/cblink/specs
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
