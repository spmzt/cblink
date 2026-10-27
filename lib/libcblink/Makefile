.include "${.CURDIR}/Makefile.inc"

LIB=		cblink
SHLIB_MAJOR=	2
INCS=		cblink.h cbl_schema.h cbl_data.h
MAN=		cblink.3

SRCS=		cbl_arena.c \
		cbl_attr.c \
		cbl_conn.c \
		cbl_ctrl.c \
		cbl_ctx.c \
		cbl_data.c \
		cbl_ddiff.c \
		cbl_dedit.c \
		cbl_dcond.c \
		cbl_dnacm.c \
		cbl_dref.c \
		cbl_dsel.c \
		cbl_decode.c \
		cbl_dump.c \
		cbl_family.c \
		cbl_frame.c \
		cbl_fw.c \
		cbl_loop.c \
		cbl_msg.c \
		cbl_notify.c \
		cbl_pattern.c \
		cbl_peer.c \
		cbl_proxy.c \
		cbl_schema.c \
		cbl_sctp.c \
		cbl_server.c \
		cbl_sock.c \
		cbl_stream.c \
		cbl_tls.c \
		cbl_uri.c \
		cbl_xpath.c \
		cbl_xpeval.c \
		cbl_ycodec.c \
		cbl_yctrl_schema.c \
		cbl_yfamily.c \
		cbl_ysub.c \
		cbl_yjson.c \
		cbl_yvalid.c \
		cbl_ymod_schema.c

# libcblink_pic.a too, of the shared library's objects: for a program
# that is built on one host and shipped to others whose libcblink may be
# older, linked in whole.
INSTALL_PIC_ARCHIVE=	yes

VERSION_DEF=	${.CURDIR}/Versions.def
SYMBOL_MAPS=	${.CURDIR}/Symbol.map

CFLAGS+=	-I${.CURDIR} ${SSL_CFLAGS} ${CBOR_CFLAGS}

.if defined(CBLINK_INTREE)
PACKAGE=	cblink
LIBADD+=	cbor ssl crypto pthread
.else
LDADD+=		${CBOR_LDADD} ${SSL_LDFLAGS} -lssl -lcrypto -lpthread -lm
# No mtree(8) hierarchy outside the tree: create the directories first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${LIBDIR} \
	    ${DESTDIR}${INCLUDEDIR} ${DESTDIR}${MANDIR}3
.endif

.include <bsd.opts.mk>

# The cblink module's structures and the control family's module are
# compiled by cblink-gen and the output is committed, with the control
# family's reference docs/ctrl.md; "make regen" refreshes them.
CBLINK_GEN?=	${.OBJDIR:H:H}/usr.bin/cblink-gen/cblink-gen
YANG_DIR?=	${.CURDIR}/../../share/yang
FW_YANG=	${YANG_DIR}/cblink@2026-10-13
CTRL_YANG=	${YANG_DIR}/cblink-ctrl@2026-10-13

regen: .PHONY
	${CBLINK_GEN} -m h,schema -b cbl_ymod -o ${.CURDIR} \
	    -s ${FW_YANG}.sid ${FW_YANG}.yang
	${CBLINK_GEN} -m h,schema -b cbl_yctrl -o ${.CURDIR} \
	    -s ${CTRL_YANG}.sid ${CTRL_YANG}.yang
	${CBLINK_GEN} -m md -b ctrl -o ${.CURDIR}/../../docs \
	    -s ${CTRL_YANG}.sid ${CTRL_YANG}.yang

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.lib.mk>

# make -j: the tests link against this library, so build them after it.
all_subdir_${DIRPRFX}tests: ${SHLIB_NAME}
