PROG=		cblink-gen
SRCS=		main.c \
		gen_c.c \
		gen_md.c \
		spec.c \
		util.c \
		yaml.c
MAN=		cblink-gen.1

# The YANG front end needs libyang 3 (net/libyang3), a developer's
# dependency only: without it the generator reads YAML specs and refuses
# YANG modules.  CBLINK_GEN_LIBYANG is yes when libyang is found, unless
# set; set to yes, it must be found.
LOCALBASE?=	/usr/local
.if !defined(CBLINK_GEN_LIBYANG)
.if exists(${LOCALBASE}/include/libyang/libyang.h)
CBLINK_GEN_LIBYANG=	yes
.else
CBLINK_GEN_LIBYANG=	no
.endif
.endif
.if ${CBLINK_GEN_LIBYANG} == "yes"
.if !exists(${LOCALBASE}/include/libyang/libyang.h)
.error CBLINK_GEN_LIBYANG=yes, but libyang is not in ${LOCALBASE}: pkg install libyang3
.endif
SRCS+=		schema.c yang.c
CFLAGS+=	-DCBLINK_GEN_LIBYANG -idirafter ${LOCALBASE}/include
LDADD+=		-L${LOCALBASE}/lib -lyang
.endif

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
