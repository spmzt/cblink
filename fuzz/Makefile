# libFuzzer harnesses for the parsers that see untrusted input: frames and
# PROXY protocol headers from the network, XPath and patterns.  Not part of
# the normal build; the sources they test are compiled in, with coverage
# instrumentation and ASan/UBSan:
#
#	make -C fuzz
#	$(make -C fuzz -V .OBJDIR)/fuzz_frame -max_total_time=300 \
#	    fuzz/corpus/frame
#
# (likewise fuzz_proxy with corpus/proxy, fuzz_xpath with corpus/xpath and fuzz_pattern with corpus/pattern; for
# long runs of fuzz_xpath and fuzz_pattern, whose inputs are many and
# small, ASAN_OPTIONS=quarantine_size_mb=16 keeps AddressSanitizer's
# quarantine of freed memory from reaching the RSS limit).  To use more
# CPUs, -jobs=N -workers=N: -fork=N was seen to hang on FreeBSD.
# Point -artifact_prefix and a first, scratch corpus directory elsewhere to
# keep new inputs out of the committed seeds.

LIB=		${.CURDIR}/../lib/libcblink
.PATH:		${LIB}

LIBSRCS!=	cd ${LIB} && echo cbl_*.c

PROGS=		fuzz_frame fuzz_proxy fuzz_xpath fuzz_pattern
SRCS.fuzz_frame=	fuzz_frame.c ${LIBSRCS}
SRCS.fuzz_proxy=	fuzz_proxy.c ${LIBSRCS}
SRCS.fuzz_xpath=	fuzz_xpath.c cbl_xpath.c
SRCS.fuzz_pattern=	fuzz_pattern.c cbl_pattern.c
MAN=

LOCALBASE?=	/usr/local
CSTD=		c23
WARNS?=		6
SANITIZE=	-fsanitize=fuzzer,address,undefined
CFLAGS+=	-g -O1 ${SANITIZE} -I${LIB} \
		-idirafter ${LOCALBASE}/include
LDFLAGS+=	${SANITIZE}
LIBS_CBLINK=	${LOCALBASE}/lib/libcbor.so -lssl -lcrypto -lpthread
LDADD.fuzz_frame=	${LIBS_CBLINK}
LDADD.fuzz_proxy=	${LIBS_CBLINK}

.include <bsd.progs.mk>
