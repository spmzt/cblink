.include "${.CURDIR}/Makefile.inc"

LIB=		cblink
SHLIB_MAJOR=	1
INCS=		cblink.h
MAN=		cblink.3

SRCS=		cbl_arena.c \
		cbl_attr.c \
		cbl_conn.c \
		cbl_ctrl.c \
		cbl_ctrl_gen.c \
		cbl_ctrl_gen_client.c \
		cbl_ctrl_gen_server.c \
		cbl_ctx.c \
		cbl_decode.c \
		cbl_dump.c \
		cbl_family.c \
		cbl_frame.c \
		cbl_loop.c \
		cbl_msg.c \
		cbl_notify.c \
		cbl_parse.c \
		cbl_peer.c \
		cbl_policy.c \
		cbl_proxy.c \
		cbl_sctp.c \
		cbl_server.c \
		cbl_sock.c \
		cbl_stream.c \
		cbl_tls.c \
		cbl_uri.c

VERSION_DEF=	${.CURDIR}/Versions.def
SYMBOL_MAPS=	${.CURDIR}/Symbol.map

CFLAGS+=	-I${.CURDIR} ${SSL_CFLAGS} ${CBOR_CFLAGS}

.if defined(CBLINK_INTREE)
PACKAGE=	cblink
LIBADD+=	cbor ssl crypto pthread
.else
LDADD+=		${CBOR_LDADD} ${SSL_LDFLAGS} -lssl -lcrypto -lpthread
# No mtree(8) hierarchy outside the tree: create the directories first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${LIBDIR} \
	    ${DESTDIR}${INCLUDEDIR} ${DESTDIR}${MANDIR}3
.endif

.include <bsd.opts.mk>

# The control family is generated from its spec by cblink-gen and the
# output is committed, with its reference docs/ctrl.md; "make regen"
# refreshes both.
CBLINK_GEN?=	${.OBJDIR:H:H}/usr.bin/cblink-gen/cblink-gen
CTRL_SPEC?=	${.CURDIR}/../../share/cblink/specs/control.yaml

regen: .PHONY
	${CBLINK_GEN} -B -b cbl_ctrl_gen -m h,c,client,server -o ${.CURDIR} \
	    ${CTRL_SPEC}
	${CBLINK_GEN} -B -b ctrl -m md -o ${.CURDIR}/../../docs ${CTRL_SPEC}

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.lib.mk>

# make -j: the tests link against this library, so build them after it.
all_subdir_${DIRPRFX}tests: ${SHLIB_NAME}
