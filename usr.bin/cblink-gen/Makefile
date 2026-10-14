PROG=		cblink-gen
SRCS=		main.c \
		gen_yang.c \
		gen_ymd.c \
		gen_yschema.c \
		gen_yserver.c \
		gen_ytree.c \
		schema.c \
		sid.c \
		sidcbor.c \
		util.c \
		yang.c
MAN=		cblink-gen.1

# YANG modules are compiled by libyang 3 (net/libyang3), the generator's
# one dependency beyond base: a developer's, not a program's.
LOCALBASE?=	/usr/local
.if !exists(${LOCALBASE}/include/libyang/libyang.h)
.error cblink-gen needs libyang in ${LOCALBASE}: pkg install libyang3
.endif
CFLAGS+=	-idirafter ${LOCALBASE}/include
LDADD+=		-L${LOCALBASE}/lib -lyang
# .sid files are JSON, read with base's libucl (private, with its header).
CFLAGS+=	-I/usr/include/private/ucl
LDADD+=		-lprivateucl
# The XPath parser and the pattern translator are libcblink's, compiled
# in.
.PATH:		${.CURDIR}/../../lib/libcblink
SRCS+=		cbl_pattern.c cbl_xpath.c
CFLAGS+=	-I${.CURDIR}/../../lib/libcblink

CSTD?=		c23
WARNS?=		6

.if !defined(SRCTOP) || defined(CBLINK_OUT_OF_TREE)
PREFIX?=	/usr/local
BINDIR?=	${PREFIX}/bin
MANDIR?=	${PREFIX}/share/man/man
TESTSBASE?=	${PREFIX}/tests
# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${BINDIR} \
	    ${DESTDIR}${MANDIR}1
.endif

.include <bsd.opts.mk>

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>

# make -j: the tests run the generator, so build them after it.
all_subdir_${DIRPRFX}tests: ${PROG}
