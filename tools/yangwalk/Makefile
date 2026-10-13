# yangwalk: the compiled YANG schema as libyang 3 gives it, a node a line.
# Not part of the build; net/libyang3 must be installed:
#
#	make -C tools/yangwalk
#	$(make -C tools/yangwalk -V .OBJDIR)/yangwalk -p dir module.yang ...

PROG=		yangwalk
MAN=

LOCALBASE?=	/usr/local
CSTD=		c23
WARNS?=		6
CFLAGS+=	-idirafter ${LOCALBASE}/include
LDADD+=		-L${LOCALBASE}/lib -lyang

.include <bsd.prog.mk>
