PACKAGE?=	tests

.if !defined(SRCTOP) || defined(CBLINK_OUT_OF_TREE)
PREFIX?=	/usr/local
TESTSBASE?=	${PREFIX}/tests
TESTSDIR=	${TESTSBASE}/cblink/cblink-gen
# atf.test.mk only knows LDADD_atf_c inside the source tree; base ships
# atf-c as a private library (headers in /usr/include).
LDADD_atf_c=	-lprivateatf-c
# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}
.endif

CSTD?=		c23
WARNS?=		6

ATF_TESTS_SH=	cblink_gen_test
ATF_TESTS_C=	roundtrip_test

GEN=		${.OBJDIR:H}/cblink-gen
LIBCBLINK_SRC=	${.CURDIR}/../../../lib/libcblink
LIBCBLINK_OBJ=	${.OBJDIR:H:H:H}/lib/libcblink

# roundtrip_test is built from code generated at build time.
GENERATED=	types.h types.c types_client.c types_server.c
CLEANFILES+=	${GENERATED}
SRCS.roundtrip_test=	types.h roundtrip_test.c types.c types_client.c \
			types_server.c
CFLAGS.roundtrip_test+=	-I${.OBJDIR} -I${LIBCBLINK_SRC}
LDADD.roundtrip_test+=	-L${LIBCBLINK_OBJ} -lcblink -lpthread -lm

.ORDER: types.h types.c types_client.c types_server.c
${GENERATED}: ${.CURDIR}/golden/types.yaml ${GEN}
	${GEN} -m h,c,client,server -o ${.OBJDIR} ${.CURDIR}/golden/types.yaml

# minimal_test: families with one kind of operation each must compile at
# WARNS=6, so the generator may not emit helpers that go unused.
ATF_TESTS_C+=	minimal_test
SRCS.minimal_test=	minimal_test.c
CFLAGS.minimal_test+=	-I${.OBJDIR} -I${LIBCBLINK_SRC}
LDADD.minimal_test+=	-L${LIBCBLINK_OBJ} -lcblink -lpthread
.for _m in onlydo onlystreams onlyevents
SRCS.minimal_test+=	${_m}.h ${_m}.c ${_m}_client.c ${_m}_server.c
CLEANFILES+=	${_m}.h ${_m}.c ${_m}_client.c ${_m}_server.c
${_m}.h: ${.CURDIR}/minimal/${_m}.yaml ${GEN}
	${GEN} -m h,c,client,server -o ${.OBJDIR} ${.CURDIR}/minimal/${_m}.yaml
${_m}.c ${_m}_client.c ${_m}_server.c: ${_m}.h
.endfor

# yang_h_test: the structs of YANG modules, every shape and type, must
# compile at WARNS=6; with a generator built with libyang only.
LOCALBASE?=	/usr/local
.if !defined(CBLINK_GEN_LIBYANG)
.if exists(${LOCALBASE}/include/libyang/libyang.h)
CBLINK_GEN_LIBYANG=	yes
.else
CBLINK_GEN_LIBYANG=	no
.endif
.endif
.if ${CBLINK_GEN_LIBYANG} == "yes"
ATF_TESTS_C+=	yang_h_test
YANGH_SRC=	${.CURDIR}/yang/shapes@2026-10-13.yang \
		${.CURDIR}/yang/ietf-system@2014-08-06.yang \
		${.CURDIR}/../../../share/yang/ietf-sid-file@2024-07-31.yang
SRCS.yang_h_test=	yangh.h yang_h_test.c
CFLAGS.yang_h_test+=	-I${.OBJDIR} -I${LIBCBLINK_SRC}
CLEANFILES+=	yangh.h
yangh.h: ${YANGH_SRC} ${GEN}
	${GEN} -m h -b yangh -o ${.OBJDIR} ${YANGH_SRC}
.endif

# Test data: the generator itself, golden files, error cases, and the
# control family spec with the files committed in lib/libcblink.
${PACKAGE}FILES+=	${GEN}
${PACKAGE}FILESMODE_${GEN}= 0555

FILESGROUPS+=	GOLDEN GOLDENTYPES GOLDENKV ERRORS CTRL CBLMK YANG
GOLDEN=		golden/types.yaml golden/kv.yaml
GOLDENDIR=	${TESTSDIR}/golden
GOLDENTYPES!=	cd ${.CURDIR} && echo golden/types/*
GOLDENTYPESDIR=	${TESTSDIR}/golden/types
GOLDENKV!=	cd ${.CURDIR} && echo golden/kv/*
GOLDENKVDIR=	${TESTSDIR}/golden/kv
ERRORS!=	cd ${.CURDIR} && echo errors/*.yaml errors/*.err
ERRORSDIR=	${TESTSDIR}/errors
CTRL=		${.CURDIR}/../../../share/cblink/specs/control.yaml \
		${LIBCBLINK_SRC}/cbl_ctrl_gen.h \
		${LIBCBLINK_SRC}/cbl_ctrl_gen.c \
		${LIBCBLINK_SRC}/cbl_ctrl_gen_client.c \
		${LIBCBLINK_SRC}/cbl_ctrl_gen_server.c \
		${.CURDIR}/../../../docs/ctrl.md
CTRLDIR=	${TESTSDIR}/ctrl
# cblink.mk, to build from specs given in each form of path.
CBLMK=		${.CURDIR}/../../../share/cblink/cblink.mk
CBLMKDIR=	${TESTSDIR}
# YANG modules for the front end.
YANG=		yang/good@2026-10-13.yang yang/bad@2026-10-13.yang \
		yang/good-dev@2026-10-13.yang yang/ext@2026-10-13.yang \
		yang/beyond@2026-10-13.yang yang/ietf-system@2014-08-06.yang \
		yang/ietf-system@2014-08-06.sid yang/iana-crypt-hash@2014-08-06.yang \
		yang/ietf-netconf-acm@2018-02-14.yang yang/subtract@2026-10-13.yang \
		yang/shapes@2026-10-13.yang yang/clash@2026-10-13.yang \
		yang/tree@2026-10-13.yang \
		${.CURDIR}/../../../share/yang/ietf-sid-file@2024-07-31.yang \
		${.CURDIR}/../../../share/yang/ietf-sid-file@2024-07-31.sid
YANGDIR=	${TESTSDIR}/yang

.for g in GOLDEN GOLDENTYPES GOLDENKV ERRORS CTRL CBLMK YANG
${g}PACKAGE=	${PACKAGE}
.endfor

.include <bsd.test.mk>
