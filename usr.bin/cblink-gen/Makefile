PROG=		cblink-gen
SRCS=		main.c \
		gen_c.c \
		gen_md.c \
		spec.c \
		util.c \
		yaml.c
MAN=		cblink-gen.1

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
