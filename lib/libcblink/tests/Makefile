.if !defined(CBLINK_INTREE)
TESTSDIR=	${TESTSBASE}/cblink/libcblink
# atf.test.mk only knows LDADD_atf_c inside the source tree; base ships
# atf-c as a private library (headers in /usr/include).
LDADD_atf_c=	-lprivateatf-c
# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}
.endif

ATF_TESTS_C=	family_test \
		frame_test \
		malformed_test \
		notify_test \
		proxy_test \
		sctp_raw_test \
		sid_test \
		ybody_test \
		stream_test \
		tcp_test \
		pattern_test \
		xpath_test

CFLAGS+=	-I${.CURDIR}/..
LDADD+=		-L${.OBJDIR:H} -lcblink -lpthread
DPADD+=		${.OBJDIR:H}/libcblink.so

# The XPath parser is internal to the library: compiled in.
.PATH:		${.CURDIR:H}
SRCS.xpath_test=	xpath_test.c cbl_xpath.c
SRCS.pattern_test=	pattern_test.c cbl_pattern.c

# YANG-CBOR written and read with libcbor itself.
CFLAGS.sid_test+=	${CBOR_CFLAGS}
.if defined(CBLINK_INTREE)
LIBADD.sid_test+=	cbor
.else
LDADD.sid_test+=	${CBOR_LDADD}
.endif

ATF_TESTS_SH=	sctp_test \
		tls_test \
		unix_test

# Helpers the atf-sh tests share.
FILESGROUPS+=	SUBR
SUBR=		cbl_test.subr
SUBRDIR=	${TESTSDIR}

# A peer program the atf-sh tests drive.
PROGS=		cbl_testpeer
BINDIR.cbl_testpeer=	${TESTSDIR}
MAN.cbl_testpeer=

.include <bsd.test.mk>
