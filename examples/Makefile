# Example programs, each built from its family spec with cblink.mk and
# exercised by tests/examples_test.sh.

SUBDIR=		echo \
		kv \
		notify \
		stream

# kvy, the kv example in YANG, needs cblink-gen built with libyang.
LOCALBASE?=	/usr/local
.if exists(${LOCALBASE}/include/libyang/libyang.h)
SUBDIR+=	kvy
.endif
SUBDIR+=	tests

.include <bsd.subdir.mk>
