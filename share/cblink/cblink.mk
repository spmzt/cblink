# cblink.mk: build a program from cblink family specs with bsd.prog.mk.
#
#	PROG=		kvd
#	SRCS=		kvd.c
#	CBLINK_SPECS=	kv.yaml
#	.include "${LOCALBASE}/share/cblink/cblink.mk"
#	.include <bsd.prog.mk>
#
# For each spec foo.yaml, cblink-gen(1) writes foo.h and the C parts named
# by CBLINK_PARTS into the object directory, and they are added to SRCS:
#
#	h	foo.h		types, parsers, builders (always generated)
#	c	foo.c		policies and parsers
#	client	foo_client.c	client wrappers
#	server	foo_server.c	server registration and reply helpers
#
# YANG modules are given instead as CBLINK_YANG, with their .sid files
# (RFC 9595) as CBLINK_SIDS; cblink-gen(1) writes, named after the first
# module or CBLINK_YANG_BASE, and adds to SRCS:
#
#	base.h		structs, their codec, the handlers' prototypes
#	base_schema.c	the schema tables, the codec's wrappers
#	base_server.c	the server's handler table (server in CBLINK_PARTS)
#
# Variables:
#	CBLINK_SPECS	family specs (YAML): absolute, or relative to ${.CURDIR}
#	CBLINK_YANG	YANG modules, name@revision.yang or name.yang, and
#	CBLINK_SIDS	their .sid files: absolute, or relative to ${.CURDIR}
#	CBLINK_YANG_BASE the outputs' name (default: the first module's)
#	CBLINK_PARTS	comma-separated parts (default: h,c,client,server)
#	CBLINK_GEN	the generator (default: ${LOCALBASE}/bin/cblink-gen)
#	CBLINK_DOCS	"yes" to also generate foo.md
#
# The program is linked with -lcblink; include paths and libraries come
# from ${LOCALBASE} unless CBLINK_CFLAGS and CBLINK_LIBS say otherwise.

.if !target(__<cblink.mk>__)
__<cblink.mk>__:

LOCALBASE?=	/usr/local
CBLINK_GEN?=	${LOCALBASE}/bin/cblink-gen
CBLINK_PARTS?=	h,c,client,server
CBLINK_CFLAGS?=	-I${LOCALBASE}/include
CBLINK_LIBS?=	-L${LOCALBASE}/lib -lcblink

CFLAGS+=	-I${.OBJDIR} ${CBLINK_CFLAGS}
LDADD+=		${CBLINK_LIBS}

_cbl_parts:=	${CBLINK_PARTS:S/,/ /g:Nmd} h
.if ${CBLINK_DOCS:Uno} == "yes"
_cbl_parts+=	md
.endif
_cbl_m:=	${_cbl_parts:O:u:ts,}

# .for variables are substituted when the loop is read, so each spec's
# names are fixed here (a "+=" of an ordinary variable would not be).
.for _spec in ${CBLINK_SPECS}
SRCS+=		${_spec:T:R}.h
CLEANFILES+=	${_spec:T:R}.h
.for _p _sfx in c .c client _client.c server _server.c md .md
.if ${_cbl_parts:M${_p}}
${_spec:T:R}${_sfx}: ${_spec:T:R}.h
CLEANFILES+=	${_spec:T:R}${_sfx}
.if ${_p} != "md"
SRCS+=		${_spec:T:R}${_sfx}
.endif
.endif
.endfor

# One generator run makes all of a spec's files: the header stands for it.
# A relative spec is relative to ${.CURDIR}.  (Not ${_spec:M/*:U...}: a .for
# variable expands as ${:U<value>}, so that :U would always apply.)
${_spec:T:R}.h: ${_spec:C,^[^/],${.CURDIR}/&,} ${CBLINK_GEN}
	${CBLINK_GEN} -m ${_cbl_m} -o ${.OBJDIR} ${.ALLSRC:[1]}
.endfor

.if !empty(CBLINK_YANG)
_cbl_yb:=	${CBLINK_YANG_BASE:U${CBLINK_YANG:[1]:T:R:C/@.*//}}
_cbl_ym:=	h,schema
SRCS+=		${_cbl_yb}.h ${_cbl_yb}_schema.c
CLEANFILES+=	${_cbl_yb}.h ${_cbl_yb}_schema.c
.if ${_cbl_parts:Mserver}
_cbl_ym:=	h,schema,server
SRCS+=		${_cbl_yb}_server.c
CLEANFILES+=	${_cbl_yb}_server.c
${_cbl_yb}_server.c: ${_cbl_yb}.h
.endif
${_cbl_yb}_schema.c: ${_cbl_yb}.h
_cbl_yang:=	${CBLINK_YANG:C,^[^/],${.CURDIR}/&,}
_cbl_sids:=	${CBLINK_SIDS:C,^[^/],${.CURDIR}/&,}
${_cbl_yb}.h: ${_cbl_yang} ${_cbl_sids} ${CBLINK_GEN}
	${CBLINK_GEN} -m ${_cbl_ym} -b ${_cbl_yb} -o ${.OBJDIR} \
	    ${_cbl_sids:S/^/-s /} ${_cbl_yang} > /dev/null
.endif

.endif	# !target(__<cblink.mk>__)
