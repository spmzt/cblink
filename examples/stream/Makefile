PROG=		cbl-stream
SRCS=		main.c
CBLINK_YANG=	stream@2026-10-13.yang
CBLINK_SIDS=	stream@2026-10-13.sid
# Its own family: no server table.
CBLINK_PARTS=	h

# In the source tree, build against the tree; elsewhere, the installed cblink.
.if exists(${.CURDIR}/../examples.mk)
.include "${.CURDIR}/../examples.mk"
.endif
.include "${CBLINK_MK:U${LOCALBASE:U/usr/local}/share/cblink/cblink.mk}"
.include <bsd.prog.mk>
