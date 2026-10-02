# Included by each example before cblink.mk.  From the source tree, the
# generator, header and library are the ones built next door, not
# installed copies.  An installed copy of an example builds against
# ${LOCALBASE} with cblink.mk's defaults instead.

TOP:=		${.PARSEDIR}/..
CBLINK_MK=	${TOP}/share/cblink/cblink.mk
CBLINK_GEN=	${.OBJDIR}/../../usr.bin/cblink-gen/cblink-gen
CBLINK_CFLAGS=	-I${TOP}/lib/libcblink
CBLINK_LIBS=	-L${.OBJDIR}/../../lib/libcblink -lcblink

CSTD?=		c23
WARNS?=		6
MAN=

PREFIX?=	/usr/local
TESTSBASE?=	${PREFIX}/tests
# The programs are test fixtures; the port installs the sources instead.
BINDIR=		${TESTSBASE}/cblink/examples
# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${BINDIR}
