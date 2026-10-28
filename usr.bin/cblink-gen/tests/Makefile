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

GEN=		${.OBJDIR:H}/cblink-gen
LIBCBLINK_SRC=	${.CURDIR}/../../../lib/libcblink
LIBCBLINK_OBJ=	${.OBJDIR:H:H:H}/lib/libcblink

# yang_h_test: the structs of YANG modules, every shape and type, must
# compile at WARNS=6.
ATF_TESTS_C+=	yang_h_test
YANGH_SRC=	${.CURDIR}/yang/shapes@2026-10-13.yang \
		${.CURDIR}/yang/edits@2026-10-14.yang \
		${.CURDIR}/yang/conds@2026-10-14.yang \
		${.CURDIR}/yang/filters@2026-10-14.yang \
		${.CURDIR}/yang/wdexample@2026-10-14.yang \
		${.CURDIR}/yang/example-last-modified@2026-10-14.yang \
		${.CURDIR}/yang/mdex@2026-10-14.yang \
		${.CURDIR}/yang/foo@2026-10-14.yang \
		${.CURDIR}/yang/bibliomod@2026-10-14.yang \
		${.CURDIR}/yang/ietf-system@2014-08-06.yang \
		${.CURDIR}/../../../share/yang/ietf-sid-file@2024-07-31.yang
# Their SIDs: RFC 9595's ietf-system completed (-a), as it leaves empty
# input and output without.
YANGH_SID=	-s ${.CURDIR}/yang/shapes@2026-10-13.sid \
		-s ${.CURDIR}/yang/edits@2026-10-14.sid \
		-s ${.CURDIR}/yang/conds@2026-10-14.sid \
		-s ${.CURDIR}/yang/filters@2026-10-14.sid \
		-s ${.CURDIR}/yang/wdexample@2026-10-14.sid \
		-s ${.CURDIR}/yang/example-last-modified@2026-10-14.sid \
		-s ${.CURDIR}/yang/mdex@2026-10-14.sid \
		-s ${.CURDIR}/yang/foo@2026-10-14.sid \
		-s ${.CURDIR}/yang/bibliomod@2026-10-14.sid \
		-s ${.OBJDIR}/ietf-system.sid \
		-s ${.CURDIR}/../../../share/yang/ietf-sid-file@2024-07-31.sid
SRCS.yang_h_test=	yangh.h yang_h_test.c yangh_schema.c yfill.c
CFLAGS.yang_h_test+=	-I${.OBJDIR} -I${LIBCBLINK_SRC}
LDADD.yang_h_test+=	-L${LIBCBLINK_OBJ} -lcblink -lpthread
# yfamily_test: family 1 serving those tables over a connection.
ATF_TESTS_C+=	yfamily_test
SRCS.yfamily_test=	yangh.h yfamily_test.c yangh_schema.c
CFLAGS.yfamily_test+=	-I${.OBJDIR} -I${LIBCBLINK_SRC} -I${LIBCBLINK_SRC}/tests
LDADD.yfamily_test+=	-L${LIBCBLINK_OBJ} -lcblink -lpthread
# Built once for all three.
CFLAGS.yangh_schema.c+=	-I${.OBJDIR} -I${LIBCBLINK_SRC}
CFLAGS.yfill.c+=	-I${LIBCBLINK_SRC}
# ydata_test: the instance tree on those tables; yedit_test, its edits.
ATF_TESTS_C+=	ydata_test yedit_test
SRCS.ydata_test=	yangh.h ydata_test.c yangh_schema.c yfill.c
CFLAGS.ydata_test+=	-I${.OBJDIR} -I${LIBCBLINK_SRC}
LDADD.ydata_test+=	-L${LIBCBLINK_OBJ} -lcblink -lpthread
SRCS.yedit_test=	yangh.h yedit_test.c yangh_schema.c yfill.c
# ymeta_test: annotations on the tree, as draft-ietf-core-yang-metadata
# writes them.
ATF_TESTS_C+=	ymeta_test
SRCS.ymeta_test=	yangh.h ymeta_test.c yangh_schema.c
CFLAGS.ymeta_test+=	-I${.OBJDIR} -I${LIBCBLINK_SRC}
LDADD.ymeta_test+=	-L${LIBCBLINK_OBJ} -lcblink -lpthread -lm
ATF_TESTS_C+=	yfilter_test
SRCS.yfilter_test=	yangh.h yfilter_test.c yangh_schema.c
CFLAGS.yfilter_test+=	-I${.OBJDIR} -I${LIBCBLINK_SRC}
LDADD.yfilter_test+=	-L${LIBCBLINK_OBJ} -lcblink -lpthread -lm
ATF_TESTS_C+=	yxpath_test
SRCS.yxpath_test=	yangh.h yxpath_test.c yangh_schema.c
CFLAGS.yxpath_test+=	-I${.OBJDIR} -I${LIBCBLINK_SRC}
LDADD.yxpath_test+=	-L${LIBCBLINK_OBJ} -lcblink -lpthread -lm
CFLAGS.yedit_test+=	-I${.OBJDIR} -I${LIBCBLINK_SRC}
LDADD.yedit_test+=	-L${LIBCBLINK_OBJ} -lcblink -lpthread
# ysub_test: family 1's subscriptions, subdemo's tables with RFC 8639's
# and RFC 8641's modules (the corpus's), numbered for the test alone.
ATF_TESTS_C+=	ysub_test
SRCS.ysub_test=	ysubh.h ysub_test.c ysubh_schema.c
CFLAGS.ysub_test+=	-I${.OBJDIR} -I${LIBCBLINK_SRC} -I${LIBCBLINK_SRC}/tests
LDADD.ysub_test+=	-L${LIBCBLINK_OBJ} -lcblink -lpthread
CFLAGS.ysubh_schema.c+=	-I${.OBJDIR} -I${LIBCBLINK_SRC}
YSUBH_SRC=	${.CURDIR}/yang/subdemo@2026-10-27.yang \
		${.CURDIR}/corpus/ietf-subscribed-notifications@2019-09-09.yang \
		${.CURDIR}/corpus/ietf-yang-push@2019-09-09.yang \
		${.CURDIR}/corpus/ietf-datastores@2018-02-14.yang
YSUBH_SID=	-s ${.CURDIR}/yang/subdemo@2026-10-27.sid \
		-s ${.CURDIR}/yang/ietf-subscribed-notifications@2019-09-09.sid \
		-s ${.CURDIR}/yang/ietf-yang-push@2019-09-09.sid \
		-s ${.CURDIR}/yang/ietf-datastores@2018-02-14.sid
CLEANFILES+=	ysubh.h ysubh_schema.c
ysubh.h: ${YSUBH_SRC} ${GEN}
	${GEN} -m h,schema -b ysubh -o ${.OBJDIR} -p ${.CURDIR}/corpus \
	    -F subdemo: -F ietf-subscribed-notifications:xpath,replay \
	    -F ietf-yang-push:on-change -F ietf-datastores: ${YSUBH_SID} \
	    ${YSUBH_SRC} > /dev/null
ysubh_schema.c: ysubh.h
# ynacm_test: NACM (RFC 8341) over family 1 and a family of its own,
# nacmdemo's tables with ietf-netconf-acm, numbered for the test alone.
ATF_TESTS_C+=	ynacm_test
SRCS.ynacm_test=	ynacmh.h ynacm_test.c ynacmh_schema.c
CFLAGS.ynacm_test+=	-I${.OBJDIR} -I${LIBCBLINK_SRC} -I${LIBCBLINK_SRC}/tests
LDADD.ynacm_test+=	-L${LIBCBLINK_OBJ} -lcblink -lpthread
CFLAGS.ynacmh_schema.c+=	-I${.OBJDIR} -I${LIBCBLINK_SRC}
YNACMH_SRC=	${.CURDIR}/yang/nacmdemo@2026-10-28.yang \
		${.CURDIR}/corpus/ietf-netconf-acm@2018-02-14.yang \
		${.CURDIR}/corpus/ietf-netconf@2011-06-01.yang
YNACMH_SID=	-s ${.CURDIR}/yang/nacmdemo@2026-10-28.sid \
		-s ${.CURDIR}/yang/ietf-netconf-acm@2018-02-14.sid \
		-s ${.CURDIR}/yang/ietf-netconf@2011-06-01.sid
CLEANFILES+=	ynacmh.h ynacmh_schema.c
ynacmh.h: ${YNACMH_SRC} ${GEN}
	${GEN} -m h,schema -b ynacmh -o ${.OBJDIR} -p ${.CURDIR}/corpus \
	    -F ietf-netconf:candidate,confirmed-commit -F nacmdemo: \
	    -F ietf-netconf-acm: ${YNACMH_SID} ${YNACMH_SRC} > /dev/null
ynacmh_schema.c: ynacmh.h
# yds_test: the datastores: running, the candidate, commit and confirmed
# commit (dsdemo's tables with ietf-netconf's), numbered for the test.
ATF_TESTS_C+=	yds_test
SRCS.yds_test=	ydsh.h yds_test.c ydsh_schema.c
CFLAGS.yds_test+=	-I${.OBJDIR} -I${LIBCBLINK_SRC} -I${LIBCBLINK_SRC}/tests
LDADD.yds_test+=	-L${LIBCBLINK_OBJ} -lcblink -lpthread
CFLAGS.ydsh_schema.c+=	-I${.OBJDIR} -I${LIBCBLINK_SRC}
YDSH_SRC=	${.CURDIR}/yang/dsdemo@2026-10-28.yang \
		${.CURDIR}/corpus/ietf-netconf@2011-06-01.yang \
		${.CURDIR}/corpus/ietf-origin@2018-02-14.yang \
		${.CURDIR}/corpus/ietf-defaults@2024-04-03.yang
YDSH_SID=	-s ${.CURDIR}/yang/dsdemo@2026-10-28.sid \
		-s ${.CURDIR}/yang/ietf-netconf@2011-06-01.sid \
		-s ${.CURDIR}/yang/ietf-origin@2018-02-14.sid \
		-s ${.CURDIR}/yang/ietf-defaults@2024-04-03.sid
CLEANFILES+=	ydsh.h ydsh_schema.c
ydsh.h: ${YDSH_SRC} ${GEN}
	${GEN} -m h,schema -b ydsh -o ${.OBJDIR} -p ${.CURDIR}/corpus \
	    -F ietf-netconf:candidate,confirmed-commit -F dsdemo: \
	    ${YDSH_SID} ${YDSH_SRC} > /dev/null
ydsh_schema.c: ydsh.h
# ymount_test: schema mount (RFC 8528): mntdemo's hosts, dsdemo mounted
# in each, through the codec, JSON, the instance tree and the validator.
ATF_TESTS_C+=	ymount_test
SRCS.ymount_test=	ymnth.h ymount_test.c ymnth_schema.c
CFLAGS.ymount_test+=	-I${.OBJDIR} -I${LIBCBLINK_SRC}
LDADD.ymount_test+=	-L${LIBCBLINK_OBJ} -lcblink -lpthread
CFLAGS.ymnth_schema.c+=	-I${.OBJDIR} -I${LIBCBLINK_SRC}
YMNTH_SRC=	${.CURDIR}/yang/mntdemo@2026-10-28.yang \
		${.CURDIR}/yang/dsdemo@2026-10-28.yang
YMNTH_SID=	-s ${.CURDIR}/yang/mntdemo@2026-10-28.sid \
		-s ${.CURDIR}/yang/dsdemo@2026-10-28.sid
CLEANFILES+=	ymnth.h ymnth_schema.c
ymnth.h: ${YMNTH_SRC} ${GEN}
	${GEN} -m h,schema -b ymnth -o ${.OBJDIR} -p ${.CURDIR}/corpus \
	    -F mntdemo: -F dsdemo: ${YMNTH_SID} ${YMNTH_SRC} > /dev/null
ymnth_schema.c: ymnth.h
# yvalid_test: the static validator on the module rules.
ATF_TESTS_C+=	yvalid_test
SRCS.yvalid_test=	rules.h yvalid_test.c rules_schema.c
CFLAGS.yvalid_test+=	-I${.OBJDIR} -I${LIBCBLINK_SRC}
LDADD.yvalid_test+=	-L${LIBCBLINK_OBJ} -lcblink -lpthread
CLEANFILES+=	rules.h rules_schema.c
rules.h: ${.CURDIR}/yang/rules@2026-10-13.yang \
    ${.CURDIR}/yang/rules@2026-10-13.sid ${GEN}
	${GEN} -m h,schema -b rules -o ${.OBJDIR} \
	    -s ${.CURDIR}/yang/rules@2026-10-13.sid \
	    ${.CURDIR}/yang/rules@2026-10-13.yang > /dev/null
rules_schema.c: rules.h
CLEANFILES+=	yangh.h yangh_schema.c ietf-system.sid
yangh.h: ${YANGH_SRC} ${GEN}
	cat ${.CURDIR}/yang/ietf-system@2014-08-06.sid > ${.OBJDIR}/ietf-system.sid
	${GEN} -n -a -s ${.OBJDIR}/ietf-system.sid \
	    ${.CURDIR}/yang/ietf-system@2014-08-06.yang > /dev/null
	${GEN} -m h,schema -b yangh -o ${.OBJDIR} ${YANGH_SID} ${YANGH_SRC} \
	    > /dev/null
yangh_schema.c: yangh.h

# Test data: the generator itself, and the files committed in
# lib/libcblink and docs from the cblink modules.
${PACKAGE}FILES+=	${GEN}
${PACKAGE}FILESMODE_${GEN}= 0555

FILESGROUPS+=	CTRL CBLMK YANG CORPUS FILL
CTRL=		${LIBCBLINK_SRC}/cbl_yctrl.h \
		${LIBCBLINK_SRC}/cbl_yctrl_schema.c \
		${LIBCBLINK_SRC}/cbl_ymod.h \
		${LIBCBLINK_SRC}/cbl_ymod_schema.c \
		${.CURDIR}/../../../docs/ctrl.md \
		${.CURDIR}/../../../fuzz/yshapes.h \
		${.CURDIR}/../../../fuzz/yshapes_schema.c
CTRLDIR=	${TESTSDIR}/ctrl
# cblink.mk, to build from modules given in each form of path.
CBLMK=		${.CURDIR}/../../../share/cblink/cblink.mk
CBLMKDIR=	${TESTSDIR}
# YANG modules for the front end.
YANG=		yang/good@2026-10-13.yang yang/bad@2026-10-13.yang \
		yang/good-dev@2026-10-13.yang yang/ext@2026-10-13.yang \
		yang/beyond@2026-10-13.yang yang/ietf-system@2014-08-06.yang \
		yang/ietf-system@2014-08-06.sid yang/iana-crypt-hash@2014-08-06.yang \
		yang/ietf-netconf-acm@2018-02-14.yang yang/subtract@2026-10-13.yang \
		yang/shapes@2026-10-13.yang yang/shapes@2026-10-13.sid \
		yang/clash@2026-10-13.yang \
		yang/tree@2026-10-13.yang \
		yang/rules@2026-10-13.yang yang/rules@2026-10-13.sid \
		yang/edits@2026-10-14.yang yang/edits@2026-10-14.sid \
		yang/conds@2026-10-14.yang yang/conds@2026-10-14.sid \
		yang/filters@2026-10-14.yang yang/filters@2026-10-14.sid \
		yang/wdexample@2026-10-14.yang yang/wdexample@2026-10-14.sid \
		yang/example-last-modified@2026-10-14.yang \
		yang/example-last-modified@2026-10-14.sid \
		yang/mdex@2026-10-14.yang yang/mdex@2026-10-14.sid \
		yang/foo@2026-10-14.yang yang/foo@2026-10-14.sid \
		yang/bibliomod@2026-10-14.yang yang/bibliomod@2026-10-14.sid \
		yang/shared@2026-10-22.yang yang/shared@2026-10-22.sid \
		yang/subdemo@2026-10-27.yang yang/subdemo@2026-10-27.sid \
		yang/ietf-subscribed-notifications@2019-09-09.sid \
		yang/ietf-yang-push@2019-09-09.sid \
		yang/ietf-datastores@2018-02-14.sid \
		yang/shared-bad@2026-10-22.yang \
		${.CURDIR}/../../../share/yang/cblink-gen@2026-10-22.yang \
		${.CURDIR}/../../../share/yang/ietf-sid-file@2024-07-31.yang \
		${.CURDIR}/../../../share/yang/ietf-sid-file@2024-07-31.sid \
		${.CURDIR}/../../../share/yang/cblink@2026-10-13.yang \
		${.CURDIR}/../../../share/yang/cblink@2026-10-13.sid \
		${.CURDIR}/../../../share/yang/cblink-ctrl@2026-10-13.yang \
		${.CURDIR}/../../../share/yang/cblink-ctrl@2026-10-13.sid
YANGDIR=	${TESTSDIR}/yang
# The corpus: the IETF and IANA modules Arcana builds on, as published
# (corpus/README.md); and the filler the round trip over them is built
# with.
CORPUS!=	cd ${.CURDIR} && echo corpus/*.yang corpus/README.md
CORPUSDIR=	${TESTSDIR}/corpus
FILL=		yfill.c yfill.h xpdiff.c
FILLDIR=	${TESTSDIR}

.for g in CTRL CBLMK YANG CORPUS FILL
${g}PACKAGE=	${PACKAGE}
.endfor

.include <bsd.test.mk>
