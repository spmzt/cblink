# Runs the example programs, installed next to this script.

PACKAGE?=	tests
PREFIX?=	/usr/local
TESTSBASE?=	${PREFIX}/tests
TESTSDIR=	${TESTSBASE}/cblink/examples

ATF_TESTS_SH=	examples_test

beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}

.include <bsd.test.mk>
