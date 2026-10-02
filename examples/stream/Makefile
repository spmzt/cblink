PROG=		cbl-stream
SRCS=		main.c
CBLINK_SPECS=	stream.yaml

# In the source tree, build against the tree; elsewhere, the installed cblink.
.if exists(${.CURDIR}/../examples.mk)
.include "${.CURDIR}/../examples.mk"
.endif
.include "${CBLINK_MK:U${LOCALBASE:U/usr/local}/share/cblink/cblink.mk}"
.include <bsd.prog.mk>
