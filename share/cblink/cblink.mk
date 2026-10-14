# cblink.mk: build a program from YANG modules with bsd.prog.mk.
#
#	PROG=		kvd
#	SRCS=		kvd.c
#	CBLINK_YANG=	kv@2026-10-13.yang
#	CBLINK_SIDS=	kv@2026-10-13.sid
#	.include "${LOCALBASE}/share/cblink/cblink.mk"
#	.include <bsd.prog.mk>
#
# The modules are given as CBLINK_YANG, with their .sid files (RFC 9595)
# as CBLINK_SIDS; cblink-gen(1) writes into the object directory, named
# after the first module or CBLINK_YANG_BASE, and adds to SRCS:
#
#	base.h		structs, their codec and message helpers, the
#			handlers' prototypes (always)
#	base_schema.c	the schema tables and the helpers (always)
#	base_server.c	the server's handler table (server in CBLINK_PARTS)
#	base.md		the modules' reference (CBLINK_DOCS=yes; not in SRCS)
#
# Variables:
#	CBLINK_YANG	YANG modules, name@revision.yang or name.yang, and
#	CBLINK_SIDS	their .sid files: absolute, or relative to ${.CURDIR}
#	CBLINK_YANG_BASE the outputs' name (default: the first module's)
#	CBLINK_PARTS	comma-separated parts (default: h,server)
#	CBLINK_GEN	the generator (default: ${LOCALBASE}/bin/cblink-gen)
#	CBLINK_DOCS	"yes" to also generate base.md
#
# The program is linked with -lcblink; include paths and libraries come
# from ${LOCALBASE} unless CBLINK_CFLAGS and CBLINK_LIBS say otherwise.

.if !target(__<cblink.mk>__)
__<cblink.mk>__:

LOCALBASE?=	/usr/local
CBLINK_GEN?=	${LOCALBASE}/bin/cblink-gen
CBLINK_PARTS?=	h,server
CBLINK_CFLAGS?=	-I${LOCALBASE}/include
CBLINK_LIBS?=	-L${LOCALBASE}/lib -lcblink

CFLAGS+=	-I${.OBJDIR} ${CBLINK_CFLAGS}
LDADD+=		${CBLINK_LIBS}

.if !empty(CBLINK_YANG)
_cbl_parts:=	${CBLINK_PARTS:S/,/ /g}
_cbl_yb:=	${CBLINK_YANG_BASE:U${CBLINK_YANG:[1]:T:R:C/@.*//}}
_cbl_ym:=	h,schema
SRCS+=		${_cbl_yb}.h ${_cbl_yb}_schema.c
CLEANFILES+=	${_cbl_yb}.h ${_cbl_yb}_schema.c
.if ${_cbl_parts:Mserver}
_cbl_ym:=	${_cbl_ym},server
SRCS+=		${_cbl_yb}_server.c
CLEANFILES+=	${_cbl_yb}_server.c
${_cbl_yb}_server.c: ${_cbl_yb}.h
.endif
.if ${CBLINK_DOCS:Uno} == "yes"
_cbl_ym:=	${_cbl_ym},md
CLEANFILES+=	${_cbl_yb}.md
${_cbl_yb}.md: ${_cbl_yb}.h
all: ${_cbl_yb}.md
.endif
${_cbl_yb}_schema.c: ${_cbl_yb}.h
# One generator run makes all the files: the header stands for them.  A
# relative path is relative to ${.CURDIR}.
_cbl_yang:=	${CBLINK_YANG:C,^[^/],${.CURDIR}/&,}
_cbl_sids:=	${CBLINK_SIDS:C,^[^/],${.CURDIR}/&,}
${_cbl_yb}.h: ${_cbl_yang} ${_cbl_sids} ${CBLINK_GEN}
	${CBLINK_GEN} -m ${_cbl_ym} -b ${_cbl_yb} -o ${.OBJDIR} \
	    ${_cbl_sids:S/^/-s /} ${_cbl_yang} > /dev/null
.endif

.endif	# !target(__<cblink.mk>__)
